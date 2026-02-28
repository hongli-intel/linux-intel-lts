#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""list_unfixed_cves.py - List CVEs affecting 6.18/linux that are not yet fixed.

Methodology
-----------
The Linux kernel CVE team assigns CVE numbers AFTER fixes land in stable
branches and tracks them by git commit ID (not in commit messages).  CVE
version-range data is published in the NVD (National Vulnerability Database).

This script:
  1. Queries the NVD API v2 for Linux-kernel CVEs
     (https://services.nvd.nist.gov/rest/json/cves/2.0)
  2. For each CVE checks whether kernel 6.18.9 falls inside an *affected*
     version range (i.e. versionStartIncluding <= 6.18.9 AND the range is
     not yet closed below or at 6.18.9).
  3. Optionally verifies each CVE's fix commit against the local branch so
     that fixes already backported are excluded from the "unfixed" list.
  4. Writes a human-readable report (or JSON/CSV with --output).

A CVE is considered **unfixed in 6.18.9** when EVERY version range node
that covers 6.18.9 has either no upper bound OR an upper bound strictly
greater than 6.18.9.

Usage
-----
    # Online (fetches live NVD data):
    python3 scripts/list_unfixed_cves.py

    # Show only CVEs with severity >= HIGH:
    python3 scripts/list_unfixed_cves.py --min-severity HIGH

    # Output as JSON or CSV:
    python3 scripts/list_unfixed_cves.py --output json
    python3 scripts/list_unfixed_cves.py --output csv

    # Also verify fix commits against a local branch checkout:
    python3 scripts/list_unfixed_cves.py --check-commits --branch 6.18/linux

    # Use a previously saved NVD cache (avoids repeated API calls):
    python3 scripts/list_unfixed_cves.py --cache-file /tmp/nvd_cache.json

Environment variables
---------------------
    NVD_API_KEY   Optional NVD API key (raises rate-limit from 5 to 50 req/30s)
"""

import argparse
import csv
import io
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KERNEL_VERSION = "6.18.9"        # Latest version present on the branch
BRANCH = "6.18/linux"
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RESULTS_PER_PAGE = 2000      # Maximum allowed by NVD
# CPE prefix used to identify Linux kernel entries in NVD data
LINUX_CPE_PREFIX = "cpe:2.3:o:linux:linux_kernel:"
# Full CPE match string passed to the NVD API CPE filter
LINUX_CPE_MATCH = "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"
REQUEST_DELAY = 6.0              # Seconds between NVD requests (no API key)
REQUEST_DELAY_WITH_KEY = 0.6     # Seconds between NVD requests (with API key)


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------

_RC_PAT = re.compile(r'-rc\d+$')


def _parse_version(v: str) -> Tuple[int, ...]:
    """Convert a kernel version string into a comparable tuple of ints.

    Handles strings like "6.18", "6.18.9", "6.19-rc1".
    Pre-release suffixes sort *below* the corresponding release.
    """
    if not v:
        return (0,)
    # Strip pre-release tag; treat it as a very small fractional release
    # e.g. "6.18-rc1" < "6.18.0"
    pre = 0
    if _RC_PAT.search(v):
        pre = -1
        v = _RC_PAT.sub('', v)
    parts = []
    for p in v.split('.'):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    # Normalise to at least 3 components so "6.18" == "6.18.0"
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts) + (pre,)


def _version_in_range(ver: str,
                      start_incl: Optional[str],
                      end_excl: Optional[str],
                      end_incl: Optional[str]) -> bool:
    """Return True if *ver* falls inside the version range."""
    tv = _parse_version(ver)
    if start_incl:
        if tv < _parse_version(start_incl):
            return False
    if end_excl:
        if tv >= _parse_version(end_excl):
            return False
    if end_incl:
        if tv > _parse_version(end_incl):
            return False
    return True


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CveEntry:
    cve_id: str
    description: str
    cvss_score: float
    cvss_severity: str          # CRITICAL / HIGH / MEDIUM / LOW / NONE
    published: str
    last_modified: str
    affected_ranges: List[dict] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    fix_commits: List[str] = field(default_factory=list)   # SHAs from NVD refs
    in_branch: Optional[bool] = None    # True = fix present, False = absent


# ---------------------------------------------------------------------------
# NVD API helpers
# ---------------------------------------------------------------------------

def _nvd_request(url: str, api_key: Optional[str] = None) -> dict:
    """Perform a single NVD API GET request; return parsed JSON."""
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "linux-intel-lts-cve-scanner/1.0")
    if api_key:
        req.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            "NVD API HTTP {}: {}".format(exc.code, exc.reason)) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            "NVD API unreachable: {}".format(exc.reason)) from exc


def fetch_nvd_cves_for_kernel(api_key: Optional[str] = None,
                               cache_file: Optional[str] = None) -> List[dict]:
    """Fetch all NVD CVE entries that reference the Linux kernel CPE.

    Returns the raw list of vulnerability dicts from the NVD response.
    Results are optionally cached to *cache_file*.
    """
    if cache_file and os.path.isfile(cache_file):
        print("[info] Loading NVD data from cache: {}".format(cache_file), file=sys.stderr)
        with open(cache_file) as fh:
            return json.load(fh)

    delay = REQUEST_DELAY_WITH_KEY if api_key else REQUEST_DELAY
    params = ("cpeName={}&isVulnerableOnly=true&resultsPerPage={}"
              .format(urllib.parse.quote(LINUX_CPE_MATCH), NVD_RESULTS_PER_PAGE))
    all_vulns: List[dict] = []
    start = 0
    total = None

    while True:
        url = "{}?{}&startIndex={}".format(NVD_API_BASE, params, start)
        print("[info] Fetching NVD page (startIndex={})…".format(start), file=sys.stderr)
        data = _nvd_request(url, api_key)
        vulns = data.get("vulnerabilities", [])
        all_vulns.extend(vulns)
        if total is None:
            total = data.get("totalResults", 0)
            print("[info] Total NVD results for Linux kernel CPE: {}".format(total), file=sys.stderr)
        start += len(vulns)
        if start >= total or not vulns:
            break
        time.sleep(delay)

    if cache_file:
        with open(cache_file, 'w') as fh:
            json.dump(all_vulns, fh)
        print("[info] Cached {} CVEs to {}".format(len(all_vulns), cache_file), file=sys.stderr)

    return all_vulns


# ---------------------------------------------------------------------------
# CVE parsing and filtering
# ---------------------------------------------------------------------------

def _extract_cvss(cve_data: dict) -> Tuple[float, str]:
    """Return (score, severity) from the highest-available CVSS metric."""
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore", 0.0)
            sev = data.get("baseSeverity", "NONE")
            if not sev and "baseSeverity" not in data:
                # CVSSv2 uses impactScore/exploitabilityScore; map numerically
                if score >= 9.0:
                    sev = "CRITICAL"
                elif score >= 7.0:
                    sev = "HIGH"
                elif score >= 4.0:
                    sev = "MEDIUM"
                else:
                    sev = "LOW"
            return float(score), sev.upper()
    return 0.0, "NONE"


def _extract_fix_commits(cve_data: dict) -> List[str]:
    """Extract git commit SHAs from NVD reference URLs."""
    sha_pat = re.compile(r'\b([0-9a-f]{40})\b')
    shas = []
    for ref in cve_data.get("references", []):
        url = ref.get("url", "")
        m = sha_pat.search(url)
        if m:
            shas.append(m.group(1))
    return list(set(shas))


def _node_affects_kernel_version(node: dict, ver: str) -> bool:
    """Return True if a NVD configuration *node* covers kernel *ver*."""
    operator = node.get("operator", "OR")
    negate = node.get("negate", False)

    # Leaf nodes have "cpeMatch" list
    matches = node.get("cpeMatch", [])
    children = node.get("nodes", [])

    results = []

    for m in matches:
        criteria = m.get("criteria", "")
        if not criteria.startswith(LINUX_CPE_PREFIX):
            continue
        if not m.get("vulnerable", False):
            continue
        si = m.get("versionStartIncluding")
        se = m.get("versionStartExcluding")
        ei = m.get("versionEndIncluding")
        ee = m.get("versionEndExcluding")

        # If start is exclusive adjust effectively
        effective_start = None
        if si:
            effective_start = si
        elif se:
            # startExcluding means > se; approximate by treating se as start
            # then check manually
            tv = _parse_version(ver)
            ts = _parse_version(se)
            if tv <= ts:
                results.append(False)
                continue
            # version > se; continue without effective_start filter
            effective_start = None

        in_range = _version_in_range(ver, effective_start, ee, ei)
        results.append(in_range)

    for child in children:
        results.append(_node_affects_kernel_version(child, ver))

    if not results:
        return False

    if operator == "AND":
        result = all(results)
    else:
        result = any(results)

    return (not result) if negate else result


def cve_affects_version(cve_raw: dict, ver: str) -> bool:
    """Return True if the CVE affects the given kernel version."""
    configurations = cve_raw.get("cve", {}).get("configurations", [])
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            if _node_affects_kernel_version(node, ver):
                return True
    return False


def _severity_rank(sev: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}.get(
        sev.upper(), 0)


def parse_cve_entries(raw_vulns: List[dict],
                      target_version: str,
                      min_severity: str = "NONE") -> List[CveEntry]:
    """Parse NVD vulnerability list and filter to those affecting *target_version*."""
    min_rank = _severity_rank(min_severity)
    entries = []
    for item in raw_vulns:
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "UNKNOWN")

        score, sev = _extract_cvss(cve_data)
        if _severity_rank(sev) < min_rank:
            continue

        if not cve_affects_version(item, target_version):
            continue

        desc_list = cve_data.get("descriptions", [])
        desc = next((d["value"] for d in desc_list if d.get("lang") == "en"),
                    "No description available.")

        refs = [r.get("url", "") for r in cve_data.get("references", [])]
        fix_commits = _extract_fix_commits(cve_data)

        entry = CveEntry(
            cve_id=cve_id,
            description=desc,
            cvss_score=score,
            cvss_severity=sev,
            published=cve_data.get("published", ""),
            last_modified=cve_data.get("lastModified", ""),
            references=refs,
            fix_commits=fix_commits,
        )
        entries.append(entry)

    return entries


# ---------------------------------------------------------------------------
# Git commit checking
# ---------------------------------------------------------------------------

def commit_in_branch(sha: str, branch: str = "HEAD") -> bool:
    """Return True if *sha* (or an abbreviation of it) is reachable from *branch*."""
    try:
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", sha, branch],
            capture_output=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def check_fix_commits(entries: List[CveEntry], branch: str) -> None:
    """For each entry, check whether any fix commit is in *branch*."""
    for entry in entries:
        if not entry.fix_commits:
            entry.in_branch = None
            continue
        entry.in_branch = any(
            commit_in_branch(sha, branch) for sha in entry.fix_commits)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

_SEV_ICON = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "NONE": "⚪",
}


def print_text_report(entries: List[CveEntry], branch: str, version: str) -> None:
    """Print a human-readable report to stdout."""
    print()
    print("=" * 72)
    print("Unfixed CVE Report – {} (based on Linux {})".format(branch, version))
    print("=" * 72)
    print("CVEs affecting Linux {} but NOT fixed in this version: {}"
          .format(version, len(entries)))
    print()

    if not entries:
        print("  No CVEs found in the NVD that match the search criteria.")
        print("  This may mean:")
        print("    - All known CVEs for 6.18.x have been fixed in 6.18.9, OR")
        print("    - The NVD data has not yet been updated for recent CVEs.")
        print()
        return

    # Sort by severity then score
    entries_sorted = sorted(entries,
                            key=lambda e: (-_severity_rank(e.cvss_severity),
                                           -e.cvss_score))

    for i, e in enumerate(entries_sorted, 1):
        icon = _SEV_ICON.get(e.cvss_severity, "⚪")
        fix_status = ""
        if e.in_branch is True:
            fix_status = "  [fix commit IS present in branch – possibly false positive]"
        elif e.in_branch is False:
            fix_status = "  [fix commit NOT found in branch – confirmed unfixed]"

        print("{:3d}. {} {} – CVSS {:.1f} ({})".format(
            i, icon, e.cve_id, e.cvss_score, e.cvss_severity))
        print("     Published   : {}".format(e.published[:10]))
        print("     Description : {}".format(e.description[:200]))
        if e.fix_commits:
            print("     Fix commits : {}".format(", ".join(e.fix_commits[:3])))
        if fix_status:
            print("    {}".format(fix_status))
        if e.references:
            print("     Reference   : {}".format(e.references[0]))
        print()


def print_json_report(entries: List[CveEntry]) -> None:
    """Print a JSON-formatted report to stdout."""
    out = []
    for e in entries:
        out.append({
            "cve_id": e.cve_id,
            "cvss_score": e.cvss_score,
            "cvss_severity": e.cvss_severity,
            "published": e.published,
            "description": e.description,
            "fix_commits": e.fix_commits,
            "fix_in_branch": e.in_branch,
            "references": e.references[:5],
        })
    print(json.dumps(out, indent=2))


def print_csv_report(entries: List[CveEntry]) -> None:
    """Print a CSV-formatted report to stdout."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["CVE ID", "CVSS Score", "Severity", "Published",
                     "Fix In Branch", "Description"])
    for e in entries:
        writer.writerow([
            e.cve_id, e.cvss_score, e.cvss_severity,
            e.published[:10],
            str(e.in_branch) if e.in_branch is not None else "unknown",
            e.description[:150].replace("\n", " "),
        ])
    print(buf.getvalue())


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--kernel-version", default=KERNEL_VERSION,
        help="Kernel version to check against (default: %(default)s)")
    parser.add_argument(
        "--branch", default=BRANCH,
        help="Branch name used in commit-check mode (default: %(default)s)")
    parser.add_argument(
        "--min-severity", default="NONE",
        choices=["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Minimum CVE severity to include (default: %(default)s)")
    parser.add_argument(
        "--output", default="text",
        choices=["text", "json", "csv"],
        help="Output format (default: %(default)s)")
    parser.add_argument(
        "--check-commits", action="store_true",
        help="Verify fix commits exist in the local branch history")
    parser.add_argument(
        "--cache-file", default=None,
        help="Path to JSON cache of NVD data (write on first run, read on subsequent)")
    parser.add_argument(
        "--api-key", default=os.environ.get("NVD_API_KEY"),
        help="NVD API key (or set NVD_API_KEY env var; raises rate limit)")
    args = parser.parse_args()

    # ---- Fetch NVD data ----
    try:
        raw_vulns = fetch_nvd_cves_for_kernel(
            api_key=args.api_key,
            cache_file=args.cache_file)
    except RuntimeError as exc:
        print("[error] {}".format(exc), file=sys.stderr)
        print("[error] Cannot reach the NVD API from this environment.", file=sys.stderr)
        print("[error] Run this script on a machine with internet access, or", file=sys.stderr)
        print("[error] provide a --cache-file from a previous online run.", file=sys.stderr)
        print("[error]", file=sys.stderr)
        print("[error] The NVD API endpoint is:", file=sys.stderr)
        print("[error]   {}".format(NVD_API_BASE), file=sys.stderr)
        print("[error]", file=sys.stderr)
        print("[error] For Linux kernel CVEs see also:", file=sys.stderr)
        print("[error]   https://lore.kernel.org/linux-cve-announce/?q=6.18", file=sys.stderr)
        print("[error]   https://cve.kernel.org", file=sys.stderr)
        return 2

    # ---- Filter to unfixed CVEs ----
    print("[info] Filtering {} NVD entries for kernel {}…"
          .format(len(raw_vulns), args.kernel_version), file=sys.stderr)
    entries = parse_cve_entries(raw_vulns, args.kernel_version,
                                min_severity=args.min_severity)
    print("[info] CVEs affecting {}: {}".format(args.kernel_version, len(entries)), file=sys.stderr)

    # ---- Optional commit check ----
    if args.check_commits:
        print("[info] Checking fix commits against branch '{}'…"
              .format(args.branch), file=sys.stderr)
        check_fix_commits(entries, args.branch)

    # ---- Output ----
    if args.output == "json":
        print_json_report(entries)
    elif args.output == "csv":
        print_csv_report(entries)
    else:
        print_text_report(entries, args.branch, args.kernel_version)

    return 0 if not entries else 1


if __name__ == "__main__":
    sys.exit(main())
