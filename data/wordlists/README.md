# Wordlists

- `common_dirs.txt` — a small curated set (~130 entries) of common paths for a
  fast default scan. This is intentionally lightweight for a graduation
  project demo; for real engagements, swap in a list from
  [SecLists](https://github.com/danielmiessler/SecLists) (e.g.
  `Discovery/Web-Content/raw-medium.txt`) by pointing `--wordlist-path` at it.
- `sensitive_files.txt` — known-sensitive paths (secrets, backups, VCS
  metadata) checked separately from the general directory list and flagged
  as high severity in the report when found.

Both files are plain text, one path per line, no leading slash.
