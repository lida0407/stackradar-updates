# StackRadar Updates

Public update feed and database catalog for the StackRadar Android demo.

StackRadar is an Android data center stack warning app. The idea is simple:
data center stacks are messy, and important changes are spread across server,
storage, hypervisor, operating system, GPU, backup, networking, security,
database, container, cloud, middleware, firmware, CVE, vendor advisory,
lifecycle, and compatibility sources.

StackRadar lets a user build a stack by choosing:

```text
Category -> brand -> series/platform family
```

Then it helps surface relevant risk, advisory, lifecycle, compatibility, and
source-monitoring signals for that stack.

## Current Coverage

Current database: `v8`

- `1,341` infrastructure entries
- `15` categories
- `215` brands/vendors
- `1,305` normalized series/platform families
- `1,257` security/advisory source mappings
- `3,565` official/tracking source mappings

Categories covered:

- Applications
- Backup & Recovery
- Cloud
- Containers
- Databases
- Drivers
- Firmware
- GPUs & Accelerators
- Middleware
- Networking
- Operating Systems
- Security
- Servers
- Storage
- Virtualization

## 3-Minute Workflow

1. Open StackRadar and choose the environment type.
2. Build the stack by selecting category, brand, and series/platform family.
3. Open **My Risks** to see risk and advisory sources related to the watched stack.
4. Open **All Risks** to browse the full database of CVE, vulnerability, security advisory, PSIRT, and vendor bulletin sources.
5. Open **News for me** or **All News** for lifecycle, release, support, compatibility, vendor, and official-source updates.

StackRadar is not a vulnerability scanner and does not inspect a network. It is
a stack-aware warning dashboard that helps identify which official, vendor, and
security sources should be checked first.

## Community Post Draft

**Title:** I vibe coded this data center stack warning app

Hi, guys,

I have been in this subreddit for a while, and recently as Fable 5 launched, I
thought maybe I could build something useful for data centers. So I built this
Android app called **StackRadar**.

The idea is simple: data center stacks are messy. You may have servers,
storage, hypervisors, operating systems, GPUs, backup software, networking,
firewalls, databases, containers, cloud platforms, middleware, and firmware all
connected. When something changes, like a CVE, vendor advisory, lifecycle
deadline, support matrix update, or compatibility notice, it is hard to know
what actually matters to your stack.

StackRadar lets you build your stack by choosing category -> brand -> series or
platform family. Then it shows relevant risks, source warnings, lifecycle
signals, and news.

Current database coverage:

- 1,341 infrastructure entries
- 15 categories
- 215 brands/vendors
- 1,305 normalized series/platform families
- 1,257 security/advisory source mappings
- 3,565 official/tracking source mappings

Categories include servers, storage, OS, virtualization, containers, GPUs,
networking, backup/recovery, security, databases, cloud, middleware,
applications, drivers, and firmware.

How to use it in about 3 minutes:

1. Choose your environment type.
2. Add your stack by category, brand, and series.
3. Open **My Risks** to see items related to your stack.
4. Open **All Risks** to browse the full CVE/security/advisory source database.
5. Open **News for me** or **All News** for lifecycle, release, support,
   compatibility, and vendor updates.

It is not a vulnerability scanner and does not inspect your network. It is more
like a stack-aware warning dashboard that helps you know which
official/vendor/security sources to check first.

Would this be useful for data center managers, MSPs, or infrastructure teams?
What would make it actually useful in your daily workflow: mobile app, web
dashboard, integrations, alerts, export reports, or something else?

## Files

- `update-manifest.json` tells the app which APK and database version are current.
- `catalog.json` is the remotely updateable technology catalog.
- APK files are distributed through GitHub Releases.
