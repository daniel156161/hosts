from __future__ import annotations

import argparse
import datetime as dt
from pathlib import Path

from tqdm import tqdm

from hosts_automation.domains import normalize_domain, read_domain_file

def custom_header() -> str:
  now = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
  return f"""# Custom hosts blocklist entries
# Manual domains and domains approved from local pfSense log review.
# Updated by hosts-automation apply-review
# Updated: {now}

"""

def load_review_domains(path: Path) -> set[str]:
  domains: set[str] = set()
  if not path.exists():
    return domains
  for line in tqdm(path.read_text(encoding="utf-8", errors="ignore").splitlines(), desc="Loading approved", unit="line"):
    if not line.strip() or line.startswith("#"):
      continue
    domain = normalize_domain(line.split()[0])
    if domain:
      domains.add(domain)
  return domains

def run(args: argparse.Namespace) -> int:
  existing = read_domain_file(args.custom)
  allowlist = read_domain_file(args.allowlist)
  approved = load_review_domains(args.approved) - allowlist
  new_domains = approved - existing
  if args.dry_run:
    print(f"Would add: {len(new_domains)}")
  else:
    args.custom.write_text(custom_header() + "\n".join(sorted(existing | approved)) + "\n", encoding="utf-8")
    print(f"Added: {len(new_domains)}")
  for domain in sorted(new_domains):
    print(domain)
  return 0

def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(description="Apply approved AI-review domains to custom.txt.")
  parser.add_argument("--approved", type=Path, default=Path("reports/ai-review/approved.txt"), help="Approved review file.")
  parser.add_argument("--custom", type=Path, default=Path("custom.txt"), help="Custom domain list to update.")
  parser.add_argument("--allowlist", type=Path, default=Path("allowlist.txt"), help="Domains that must never be blocked.")
  parser.add_argument("--dry-run", action="store_true", help="Show domains without changing blocklist.")
  return parser

def main(argv: list[str] | None = None) -> int:
  return run(build_parser().parse_args(argv))

if __name__ == "__main__":
  raise SystemExit(main())
