from __future__ import annotations

import argparse
import collections
import datetime as dt
import re
from pathlib import Path

from tqdm import tqdm

from hosts_automation.domains import normalize_domain, read_domain_file, strip_inline_comment

SUSPICIOUS_KEYWORDS = {
  "ad",
  "ads",
  "advert",
  "analytics",
  "beacon",
  "click",
  "collect",
  "crash",
  "crashlytics",
  "event",
  "metric",
  "metrics",
  "pixel",
  "stat",
  "stats",
  "telemetry",
  "track",
  "tracker",
  "tracking",
}
RANDOM_LABEL_RE = re.compile(r"^(?=.*[a-z])(?=.*\d)[a-z0-9-]{16,}$")

def domains_from_log_line(line: str) -> list[str]:
  line = strip_inline_comment(line)
  if not line:
    return []
  domains: list[str] = []
  for token in re.split(r"[\s,;|]+", line):
    token = token.strip("'\"[](),")
    if not token or token.startswith("/"):
      continue
    domain = normalize_domain(token)
    if domain:
      domains.append(domain)
  return domains

def score_domain(domain: str, count: int) -> tuple[int, list[str]]:
  labels = domain.split(".")
  reasons: list[str] = []
  score = 0

  matched = sorted(keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in labels or any(label.startswith(keyword + "-") for label in labels))
  if matched:
    score += min(30, 10 * len(matched))
    reasons.append("keywords=" + ",".join(matched[:5]))

  if any(RANDOM_LABEL_RE.match(label) for label in labels[:-1]):
    score += 25
    reasons.append("random-looking-label")

  if count >= 100:
    score += 25
    reasons.append(f"high-volume={count}")
  elif count >= 20:
    score += 15
    reasons.append(f"medium-volume={count}")
  elif count >= 5:
    score += 5
    reasons.append(f"repeated={count}")

  if len(labels) >= 5:
    score += 10
    reasons.append("deep-subdomain")

  return score, reasons

def discover(args: argparse.Namespace) -> int:
  blocked = read_domain_file(args.blocklist)
  allowlist = read_domain_file(args.allowlist)
  counts: collections.Counter[str] = collections.Counter()

  for log_path in tqdm(args.logs, desc="Reading logs", unit="file"):
    for line in log_path.read_text(encoding="utf-8", errors="ignore").splitlines():
      counts.update(domains_from_log_line(line))

  candidates: list[tuple[int, int, str, list[str]]] = []
  for domain, count in tqdm(counts.items(), desc="Scoring domains", unit="domain"):
    if domain in blocked or domain in allowlist:
      continue
    if any(domain.endswith("." + blocked_domain) for blocked_domain in blocked):
      continue
    score, reasons = score_domain(domain, count)
    if score >= args.min_score:
      candidates.append((score, count, domain, reasons))

  candidates.sort(key=lambda item: (-item[0], -item[1], item[2]))
  now = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
  lines = [
    "# Review candidates generated from local DNS/pfBlockerNG logs.",
    "# Do not feed this file directly into pfBlockerNG without review.",
    f"# Updated: {now}",
    "# format: domain # score=<score> count=<count> reasons=<reasons>",
    "",
  ]
  for score, count, domain, reasons in candidates[: args.limit]:
    lines.append(f"{domain} # score={score} count={count} reasons={','.join(reasons)}")
  lines.append("")
  args.output.write_text("\n".join(lines), encoding="utf-8")

  print(f"Log domains seen: {len(counts)}")
  print(f"Candidates written: {min(len(candidates), args.limit)}")
  print(f"Output: {args.output}")
  return 0

def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(description="Find review-only block candidates from DNS/pfBlockerNG logs.")
  parser.add_argument("logs", nargs="+", type=Path, help="Log files to scan. Copy them from pfSense or mount them locally first.")
  parser.add_argument("--blocklist", type=Path, default=Path("block.txt"), help="Current blocked domains.")
  parser.add_argument("--allowlist", type=Path, default=Path("allowlist.txt"), help="Domains to ignore.")
  parser.add_argument("--output", type=Path, default=Path("candidates.txt"), help="Review output file.")
  parser.add_argument("--min-score", type=int, default=15, help="Minimum heuristic score.")
  parser.add_argument("--limit", type=int, default=500, help="Maximum candidates to write.")
  return parser

def main(argv: list[str] | None = None) -> int:
  return discover(build_parser().parse_args(argv))

if __name__ == "__main__":
  raise SystemExit(main())
