#!/usr/bin/env python3
"""Build real risk/news intelligence feeds for the StackRadar database.

Pulls two free, authoritative sources and merges them into catalog.json as
explicit `risks` and `news` arrays (the Android app renders these on top of
its catalog-derived source-monitoring entries):

  * CISA Known Exploited Vulnerabilities (KEV) -> "Act Now" risks
  * endoflife.date lifecycle API             -> "Plan" risks + Lifecycle news

It also regenerates update-manifest.json with the new database version and a
SHA-256 checksum of catalog.json, which the app verifies before applying an
update. Pass --apk to embed the checksum of a release APK as well.

The database version is only bumped when feed content actually changed, so a
daily cron produces no churn on quiet days.

Stdlib only. Usage:
    python3 tools/build_intel_feeds.py --catalog catalog.json --manifest update-manifest.json
"""

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
import time
import urllib.request

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EOL_INDEX_URL = "https://endoflife.date/api/all.json"
EOL_PRODUCT_URL = "https://endoflife.date/api/{slug}.json"
USER_AGENT = "StackRadar-IntelFeeds/1.0 (+https://github.com/lida0407/stackradar)"

# Curated catalog-name -> endoflife.date slug hints for products whose names
# do not normalize to the slug automatically. Extend freely.
EOL_SLUG_OVERRIDES = {
    "ubuntu server": "ubuntu",
    "red hat enterprise linux": "rhel",
    "suse linux enterprise server": "sles",
    "windows server": "windows-server",
    "vmware esxi": "esxi",
    "vmware vcenter server": "vcenter",
    "vmware vsphere": "esxi",
    "proxmox ve": "proxmox-ve",
    "azure stack hci": "azure-stack-hci",
    "veeam backup & replication": "veeam-backup-and-replication",
    "microsoft sql server": "mssqlserver",
    "oracle database": "oracle-database",
    "apache http server": "apache",
    "apache tomcat": "tomcat",
    "apache kafka": "apache-kafka",
    "apache activemq": "apache-activemq",
    "docker engine": "docker-engine",
    "amazon eks": "amazon-eks",
    "red hat openshift": "red-hat-openshift",
}

KEV_RECENT_DAYS = 120        # KEV additions younger than this become Act Now risks
KEV_NEWS_DAYS = 30           # ... and additionally news items when this fresh
KEV_MAX_PER_PRODUCT = 3
EOL_HORIZON_DAYS = 540       # upcoming EOL milestones within this window become Plan risks
EOL_NEWS_PAST_DAYS = 90      # recently passed milestones stay visible as news
EOL_MAX_CYCLES_PER_PRODUCT = 2


def log(message):
    print(message, file=sys.stderr)


def fetch_json(url, retries=3):
    last = None
    for attempt in range(retries):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as error:  # noqa: BLE001 - retry any transport error
            last = error
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"Failed to fetch {url}: {last}")


def normalize(value):
    return re.sub(r"[^a-z0-9]+", "", (value or "").lower())


# Words too generic to establish a product match on their own.
GENERIC_TOKENS = {
    "server", "servers", "software", "platform", "suite", "service", "services",
    "edition", "enterprise", "manager", "management", "system", "systems",
    "appliance", "cloud", "data", "center", "windows", "linux", "web", "pro",
    "plus", "client", "agent", "gateway", "controller", "security", "network",
}


def tokens(value):
    return [t for t in re.split(r"[^a-z0-9]+", (value or "").lower()) if len(t) >= 3]


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 16), b""):
            digest.update(block)
    return digest.hexdigest()


# --------------------------------------------------------------------------
# CISA KEV -> Act Now risks
# --------------------------------------------------------------------------

def kev_matches_entry(kev, entry):
    """Vendor must match, and the KEV product must overlap the catalog name."""
    kev_vendor = normalize(kev.get("vendorProject"))
    entry_vendor = normalize(entry.get("vendor"))
    if not kev_vendor or not entry_vendor:
        return False
    if kev_vendor not in entry_vendor and entry_vendor not in kev_vendor:
        return False
    kev_product = normalize(kev.get("product"))
    entry_name = normalize(entry.get("name"))
    if not kev_product or not entry_name:
        return False
    if kev_product in entry_name or entry_name in kev_product:
        return True
    kev_tokens = set(tokens(kev.get("product")))
    name_tokens = set(tokens(entry.get("name")))
    vendor_tokens = set(tokens(entry.get("vendor"))) | set(tokens(kev.get("vendorProject")))
    # Require a distinctive shared token: not the vendor name, not a generic word.
    distinctive = (kev_tokens & name_tokens) - vendor_tokens - GENERIC_TOKENS
    return bool(distinctive)


def build_kev_items(kev_feed, catalog, today):
    cutoff = today - dt.timedelta(days=KEV_RECENT_DAYS)
    news_cutoff = today - dt.timedelta(days=KEV_NEWS_DAYS)
    risks, news = [], []
    per_product = {}
    vulnerabilities = sorted(
        kev_feed.get("vulnerabilities", []),
        key=lambda v: v.get("dateAdded", ""),
        reverse=True,
    )
    for kev in vulnerabilities:
        try:
            added = dt.date.fromisoformat(kev.get("dateAdded", ""))
        except ValueError:
            continue
        if added < cutoff:
            continue
        for entry in catalog:
            if not kev_matches_entry(kev, entry):
                continue
            if per_product.setdefault(entry["id"], 0) >= KEV_MAX_PER_PRODUCT:
                continue
            per_product[entry["id"]] += 1
            cve = kev.get("cveID", "").strip()
            ransomware = kev.get("knownRansomwareCampaignUse", "") == "Known"
            why = [
                f"{cve} was added to the CISA Known Exploited Vulnerabilities catalog on {added.isoformat()}.",
                "CISA lists this vulnerability as exploited in the wild.",
            ]
            if ransomware:
                why.append("CISA associates this vulnerability with known ransomware campaigns.")
            due = kev.get("dueDate", "")
            if due:
                why.append(f"CISA remediation due date for US federal agencies: {due}.")
            risks.append({
                "id": f"kev-{cve.lower()}-{entry['id']}",
                "bucket": "act",
                "tier": "ACT NOW",
                "tone": "red",
                "product": entry["name"],
                "title": f"{cve} ({kev.get('vulnerabilityName', 'exploited vulnerability')}) is in the CISA KEV catalog",
                "infrastructure_category": entry.get("category", "Applications"),
                "brand": entry.get("vendor", ""),
                "updated": added.isoformat(),
                "why": why,
                "match": "Product Family Match",
                "matchTone": "amber",
                "conf": "High",
                "sources": ["CISA KEV", "NVD"],
                "cta": "Review Action",
                "what": kev.get("shortDescription", "").strip()
                        or f"{cve} affecting {kev.get('vendorProject')} {kev.get('product')} has confirmed exploitation evidence.",
                "whyD": f"Your database maps this product family ({entry['name']}) to this vendor. "
                        "Exploited vulnerabilities are prioritized above all other signals.",
                "affected": "Verify version",
                "affTone": "amber",
                "affNote": "KEV matching is at product-family level. Compare your exact installed version against the affected versions in the NVD record and vendor advisory.",
                "steps": [
                    "Confirm the exact installed version",
                    f"Open the NVD record for {cve}",
                    kev.get("requiredAction", "").strip() or "Apply vendor mitigations or patches",
                    "Check whether the product is internet-facing and restrict exposure",
                ],
                "srcCards": [
                    {
                        "n": "CISA Known Exploited Vulnerabilities",
                        "t": "Government security authority",
                        "badge": "Government",
                        "pub": added.isoformat(),
                        "chk": today.isoformat(),
                    },
                    {
                        "n": f"NVD record {cve}",
                        "t": "Government vulnerability database",
                        "badge": "Government",
                        "pub": added.isoformat(),
                        "chk": today.isoformat(),
                    },
                ],
            })
            if added >= news_cutoff:
                news.append({
                    "id": f"kev-news-{cve.lower()}-{entry['id']}",
                    "vendor": entry.get("vendor", "CISA"),
                    "tag": "Security",
                    "title": f"{cve} added to CISA KEV catalog ({kev.get('product', '')})",
                    "source": "CISA Known Exploited Vulnerabilities catalog",
                    "badge": "Government",
                    "date": added.isoformat(),
                    "infrastructure_category": entry.get("category", "Applications"),
                    "brand": entry.get("vendor", ""),
                    "rel": [entry["name"]],
                    "why": f"The database maps {entry['name']} to this vendor and CISA confirmed active exploitation.",
                })
    return risks, news


# --------------------------------------------------------------------------
# endoflife.date -> Plan risks + Lifecycle news
# --------------------------------------------------------------------------

def eol_slug_for_entry(entry, slugs):
    name = (entry.get("name") or "").lower().strip()
    if name in EOL_SLUG_OVERRIDES and EOL_SLUG_OVERRIDES[name] in slugs:
        return EOL_SLUG_OVERRIDES[name]
    normalized = normalize(name)
    if normalized in slugs:
        return normalized
    hyphenated = re.sub(r"[^a-z0-9]+", "-", name).strip("-")
    if hyphenated in slugs:
        return hyphenated
    return None


def parse_eol_field(value):
    """endoflife.date `eol`/`support` fields are either ISO dates or booleans."""
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            return None
    return None


def build_eol_items(catalog, today, fetch=fetch_json):
    slugs = set(fetch(EOL_INDEX_URL))
    horizon = today + dt.timedelta(days=EOL_HORIZON_DAYS)
    recent_past = today - dt.timedelta(days=EOL_NEWS_PAST_DAYS)
    risks, news = [], []
    matched = 0
    seen_slugs = {}
    for entry in catalog:
        slug = eol_slug_for_entry(entry, slugs)
        if not slug:
            continue
        if slug not in seen_slugs:
            try:
                seen_slugs[slug] = fetch(EOL_PRODUCT_URL.format(slug=slug))
            except RuntimeError as error:
                log(f"  skip {slug}: {error}")
                seen_slugs[slug] = []
        cycles = seen_slugs[slug]
        matched += 1
        emitted = 0
        for cycle in cycles:
            if emitted >= EOL_MAX_CYCLES_PER_PRODUCT:
                break
            eol_date = parse_eol_field(cycle.get("eol"))
            if eol_date is None or eol_date > horizon or eol_date < recent_past:
                continue
            cycle_name = str(cycle.get("cycle", ""))
            passed = eol_date < today
            emitted += 1
            product_label = f"{entry['name']} {cycle_name}".strip()
            risks.append({
                "id": f"eol-{slug}-{normalize(cycle_name)}-{entry['id']}",
                "bucket": "plan",
                "tier": "PLAN",
                "tone": "blue",
                "product": entry["name"],
                "title": (f"{product_label} reached end of life on {eol_date.isoformat()}"
                          if passed else
                          f"{product_label} reaches end of life on {eol_date.isoformat()}"),
                "infrastructure_category": entry.get("category", "Applications"),
                "brand": entry.get("vendor", ""),
                "updated": today.isoformat(),
                "why": [
                    f"endoflife.date tracks the {cycle_name} cycle of {entry['name']}.",
                    ("This cycle no longer receives security fixes." if passed
                     else "Plan the migration before security fixes stop."),
                ],
                "match": "Product Family Match",
                "matchTone": "gray",
                "conf": "High",
                "sources": ["endoflife.date"],
                "cta": "",
                "what": f"The {cycle_name} release cycle of {entry['name']} "
                        + ("passed its end-of-life date." if passed else "approaches its end-of-life date."),
                "whyD": "Running end-of-life infrastructure means no security patches and usually no vendor support.",
                "affected": "Verify version",
                "affTone": "gray",
                "affNote": f"Only deployments on the {cycle_name} cycle are affected. Confirm the running version.",
                "steps": [
                    "Confirm which release cycle is deployed",
                    "Check the vendor lifecycle page for extended-support options",
                    "Schedule the upgrade or migration before the milestone",
                ],
                "srcCards": [{
                    "n": f"endoflife.date/{slug}",
                    "t": "Aggregated official lifecycle data",
                    "badge": "High Authority",
                    "pub": eol_date.isoformat(),
                    "chk": today.isoformat(),
                }],
            })
            news.append({
                "id": f"eol-news-{slug}-{normalize(cycle_name)}-{entry['id']}",
                "vendor": entry.get("vendor", ""),
                "tag": "Lifecycle",
                "title": (f"{product_label} is past end of life ({eol_date.isoformat()})"
                          if passed else
                          f"{product_label} end of life scheduled for {eol_date.isoformat()}"),
                "source": "endoflife.date lifecycle data",
                "badge": "High Authority",
                "date": eol_date.isoformat(),
                "infrastructure_category": entry.get("category", "Applications"),
                "brand": entry.get("vendor", ""),
                "rel": [entry["name"]],
                "why": f"A lifecycle milestone applies to the {cycle_name} cycle of {entry['name']}.",
            })
    log(f"  endoflife.date: matched {matched} catalog entries across {len(seen_slugs)} products")
    return risks, news


# --------------------------------------------------------------------------
# Assembly
# --------------------------------------------------------------------------

def content_fingerprint(document):
    trimmed = {k: v for k, v in document.items() if k not in ("databaseVersion", "updatedAt")}
    return hashlib.sha256(json.dumps(trimmed, sort_keys=True).encode("utf-8")).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", default="catalog.json")
    parser.add_argument("--manifest", default="update-manifest.json")
    parser.add_argument("--apk", help="Path to a release APK; its SHA-256 is written to the manifest app section")
    parser.add_argument("--app-version-code", type=int, help="Override app.versionCode in the manifest")
    parser.add_argument("--app-version-name", help="Override app.versionName in the manifest")
    parser.add_argument("--force", action="store_true", help="Bump the database version even without content changes")
    args = parser.parse_args()

    today = dt.date.today()
    with open(args.catalog, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    catalog = document.get("catalog", [])
    log(f"Loaded catalog with {len(catalog)} entries (v{document.get('databaseVersion')})")

    log("Fetching CISA KEV catalog...")
    kev_feed = fetch_json(KEV_URL)
    kev_risks, kev_news = build_kev_items(kev_feed, catalog, today)
    log(f"  KEV: {len(kev_risks)} Act Now risks, {len(kev_news)} news items")

    log("Fetching endoflife.date lifecycle data...")
    eol_risks, eol_news = build_eol_items(catalog, today)
    log(f"  EOL: {len(eol_risks)} Plan risks, {len(eol_news)} news items")

    old_fingerprint = content_fingerprint(document)
    document["risks"] = kev_risks + eol_risks
    document["news"] = sorted(kev_news + eol_news, key=lambda n: n["date"], reverse=True)

    changed = content_fingerprint(document) != old_fingerprint or args.force
    manifest_only = bool(args.apk or args.app_version_code or args.app_version_name)
    if not changed and not manifest_only:
        log("No feed changes since the last run; catalog and manifest left untouched.")
        return

    if changed:
        document["databaseVersion"] = int(document.get("databaseVersion", 0)) + 1
        document["updatedAt"] = today.isoformat()
        with open(args.catalog, "w", encoding="utf-8") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        log(f"Wrote {args.catalog} as v{document['databaseVersion']}")
    else:
        log("Feeds unchanged; updating manifest only.")

    with open(args.manifest, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    database = manifest.setdefault("database", {})
    database["version"] = document["databaseVersion"]
    database["sha256"] = sha256_file(args.catalog)
    database["notes"] = (f"v{document['databaseVersion']}: {len(kev_risks)} CISA KEV Act Now risks, "
                         f"{len(eol_risks)} lifecycle Plan risks, {len(document['news'])} news items "
                         f"(generated {today.isoformat()}).")
    app = manifest.setdefault("app", {})
    if args.apk:
        app["sha256"] = sha256_file(args.apk)
    if args.app_version_code:
        app["versionCode"] = args.app_version_code
    if args.app_version_name:
        app["versionName"] = args.app_version_name
    with open(args.manifest, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    log(f"Wrote {args.manifest} (database sha256 {database['sha256'][:16]}...)")


if __name__ == "__main__":
    main()
