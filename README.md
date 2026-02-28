linux-intel-lts
================

This is a fork of the Intel Linux LTS kernel repository.

Branch Count
------------

The fork currently contains **3 main branches**:

| # | Branch | Description |
|---|--------|-------------|
| 1 | `master` | Follows kernel.org master; updated periodically |
| 2 | `6.18/linux` | Intel LTS 6.18 Linux kernel with Intel patches |
| 3 | `6.18/linux-cve` | CVE fixes for the 6.18 Linux kernel |

CVE Analysis for `6.18/linux`
------------------------------

The `6.18/linux` branch is based on Linux **6.18.9** (released Feb 2026),
which incorporates all stable maintenance releases from 6.18.1 through 6.18.9.

### CVE Tracking Methodology

Linux kernel CVEs are **not** embedded directly in individual commit messages.
Instead, the Linux kernel CVE team assigns identifiers after a fix is merged
into a stable kernel tree and tracks each CVE by its upstream git commit ID.
The full list of assigned CVEs is published on the
[linux-cve-announce mailing list](https://lore.kernel.org/linux-cve-announce/).

See [`Documentation/process/cve.rst`](Documentation/process/cve.rst) for
the official Linux kernel CVE process.

### Scanning Commit Messages for CVE Tags

The script [`scripts/scan_cves.py`](scripts/scan_cves.py) scans commit
messages for explicit `CVE-XXXX-XXXXX` identifiers.

```bash
# Scan the current branch
python3 scripts/scan_cves.py --branch 6.18/linux

# Scan only commits since a specific date
python3 scripts/scan_cves.py --branch 6.18/linux --since 2025-01-01
```

**Result:** `0` CVE identifiers appear explicitly in the commit messages
of the `6.18/linux` branch (consistent with the upstream Linux kernel
convention of tracking CVEs externally by commit ID).

### Known CVE Fixes in 6.18.x Stable Releases

The 6.18.1 – 6.18.9 stable releases collectively include **351+** upstream
cherry-picked fixes per release cycle. The Linux kernel CVE team assigns
CVE numbers to any potentially security-relevant fix; for the 6.18.x series
these assignments are published at:

> <https://lore.kernel.org/linux-cve-announce/?q=6.18>
