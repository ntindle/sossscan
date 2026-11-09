# Security policy

## Reporting a vulnerability

Please don't open a public issue, discussion or pull request for a vulnerability. Report it privately through GitHub instead:
https://github.com/ntindle/sossscan/security/advisories/new

Say what you found, how to reproduce it, and what someone could do with it.

## Scope

- **The scanner:** `lib/scanner/` and the downloadable CLI built from it (`sosf-scan.mjs`).
- **The site:** https://sossscan.ntindle.com, its API and the page.
- **The GitHub App** (`sossscan`): sign-in, and how the server uses the app's permissions, including the settings changes and pull requests it makes. If the app did anything to a repository that nobody asked for, report that too.

Out of scope: problems the scanner finds in other people's repositories (report those to that project), and the known limitations listed in the README.

## What to expect

sossscan is a spare-time project with one maintainer, so replies can take a while. The aim is to acknowledge a report within a week, keep you posted while it's being fixed, and credit you in the advisory unless you'd rather not be named. There's no bug bounty.

## Supported versions

Fixes go to the live site and to `main`. The downloadable scanner is built from `main`, so download it again to get them.
