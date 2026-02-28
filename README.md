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

---

Unfixed CVEs for `6.18/linux`
------------------------------

The second script, [`scripts/list_unfixed_cves.py`](scripts/list_unfixed_cves.py),
identifies CVEs that were **introduced before Linux 6.18** (i.e. the vulnerable
code existed in the kernel) but have **not yet been fixed in 6.18.9**.

### Methodology

A CVE is classified as *unfixed in 6.18.9* when the NVD version-range data
shows:

```
versionStartIncluding ≤ 6.18.9
     AND
versionEndExcluding   > 6.18.9   (or no upper bound at all)
```

Optionally the script also cross-checks each CVE's fix commit SHA (extracted
from NVD reference URLs) against the local git history of the branch to
reduce false positives caused by stale NVD data.

### Running the Script

```bash
# Requires internet access to query the NVD API:
python3 scripts/list_unfixed_cves.py

# Show only HIGH and CRITICAL CVEs:
python3 scripts/list_unfixed_cves.py --min-severity HIGH

# Output as JSON (machine-readable):
python3 scripts/list_unfixed_cves.py --output json

# Cross-check fix commits against a local branch:
python3 scripts/list_unfixed_cves.py --check-commits --branch 6.18/linux

# Speed up repeated runs with a local cache file:
python3 scripts/list_unfixed_cves.py --cache-file /tmp/nvd_kernel.json

# Set an NVD API key for a higher rate limit (50 req/30 s vs 5):
export NVD_API_KEY=<your-key>
python3 scripts/list_unfixed_cves.py
```

### Data Sources

| Source | URL |
|--------|-----|
| NVD API v2 (primary) | <https://services.nvd.nist.gov/rest/json/cves/2.0> |
| Linux kernel CVE announcements | <https://lore.kernel.org/linux-cve-announce/?q=6.18> |
| Kernel CVE tracker | <https://cve.kernel.org> |
| Linux kernel CVE process docs | [`Documentation/process/cve.rst`](Documentation/process/cve.rst) |

### Important Note on CVE Counts

Because the Linux kernel CVE team assigns identifiers *after* a fix is merged
into a stable branch, and because the NVD may lag behind new kernel releases,
the count of "unfixed CVEs" returned by this script should be interpreted as
a **lower bound** on the actual exposure: some recently discovered issues may
not yet have a CVE assigned or may not yet appear in the NVD.
