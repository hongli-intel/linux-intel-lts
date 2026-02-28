#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# Scan a kernel branch for CVE references in commit messages.
#
# Usage:
#   python3 scripts/scan_cves.py [--branch <branch>] [--since <date>]
#
# Examples:
#   python3 scripts/scan_cves.py
#   python3 scripts/scan_cves.py --branch 6.18/linux
#   python3 scripts/scan_cves.py --branch 6.18/linux --since 2025-01-01

import subprocess
import re
import sys
import argparse
from collections import defaultdict

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

def get_commits(branch, since=None, base=None):
    """Return list of (sha, message) tuples for commits on branch."""
    cmd = ['git', 'log', '--format=%H%x00%B%x00---END---']
    if since:
        cmd += ['--since', since]
    if base:
        cmd += ['{}..{}'.format(base, branch)]
    else:
        cmd += [branch]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print('Error running git log: {}'.format(e.stderr), file=sys.stderr)
        sys.exit(1)

    commits = []
    for entry in result.stdout.split('---END---\n'):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split('\x00', 2)
        if len(parts) >= 2:
            sha = parts[0].strip()
            message = parts[1].strip() if len(parts) > 1 else ''
            commits.append((sha, message))
    return commits

def scan_cves(commits):
    """Return dict mapping CVE ID -> list of commit SHAs that mention it."""
    cve_map = defaultdict(list)
    for sha, message in commits:
        cves = set(CVE_PATTERN.findall(message))
        for cve in cves:
            cve_map[cve.upper()].append(sha[:12])
    return cve_map

def print_summary(branch, cve_map, total_commits):
    print('=' * 60)
    print('CVE Scan Report for branch: {}'.format(branch))
    print('=' * 60)
    print('Total commits scanned : {}'.format(total_commits))
    print('CVEs found in messages: {}'.format(len(cve_map)))
    print()
    if cve_map:
        print('CVE ID           Commits')
        print('-' * 50)
        for cve in sorted(cve_map):
            print('{:<20} {}'.format(cve, ', '.join(cve_map[cve])))
    else:
        print('No CVE identifiers found directly in commit messages.')
        print()
        print('Note: Linux kernel CVEs are assigned AFTER fixes land in')
        print('stable branches and are tracked externally by the kernel')
        print('CVE team. See Documentation/process/cve.rst and')
        print('https://lore.kernel.org/linux-cve-announce/ for the full')
        print('list of CVEs fixed in this kernel series.')
    print()

def main():
    parser = argparse.ArgumentParser(
        description='Scan a kernel branch for CVE references in commit messages.')
    parser.add_argument('--branch', default='HEAD',
                        help='Branch to scan (default: HEAD)')
    parser.add_argument('--base', default=None,
                        help='Base ref; if set, only commits on top of base are scanned')
    parser.add_argument('--since', default=None,
                        help='Only consider commits newer than this date (e.g. 2025-01-01)')
    args = parser.parse_args()

    commits = get_commits(args.branch, since=args.since, base=args.base)
    cve_map = scan_cves(commits)
    print_summary(args.branch, cve_map, len(commits))
    return 0 if cve_map else 1

if __name__ == '__main__':
    sys.exit(main())
