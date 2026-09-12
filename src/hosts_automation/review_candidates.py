from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tqdm import tqdm

BLOCK_LABELS = {"ads", "tracking", "telemetry", "malware", "phishing", "scam", "malvertising"}
SAFE_LABELS = {"benign", "infrastructure", "cdn", "cloud-provider", "already-blocked"}
DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_ENDPOINT = "https://api.openai.com/v1/chat/completions"

@dataclass
class Review:
  domain: str
  label: str
  decision: str
  confidence: float
  reason: str

def load_inspections(path: Path, limit: int) -> list[dict[str, Any]]:
  rows: list[dict[str, Any]] = []
  for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
    if not line.strip():
      continue
    row = json.loads(line)
    if row.get("domain"):
      rows.append(row)
    if len(rows) >= limit:
      break
  return rows

def compact_evidence(row: dict[str, Any]) -> dict[str, Any]:
  return {
    "domain": row.get("domain"),
    "url": row.get("url"),
    "status": row.get("status"),
    "final_url": row.get("final_url"),
    "content_type": row.get("content_type"),
    "title": row.get("title"),
    "meta": row.get("meta"),
    "snippet": (row.get("snippet") or "")[:800],
    "inspection_classification": row.get("classification"),
    "inspection_reasons": row.get("reasons"),
    "error": row.get("error"),
  }

def heuristic_review(row: dict[str, Any]) -> Review:
  domain = row["domain"]
  haystack = " ".join(
    str(value or "")
    for value in [domain, row.get("final_url"), row.get("title"), row.get("snippet"), row.get("server"), json.dumps(row.get("meta") or {})]
  ).lower()
  already_blocked = (
    row.get("classification") == "already-blocked"
    or "pfblockerng-dnsbl" in (row.get("reasons") or [])
    or "pfblockerng dnsbl" in haystack
    or "site blocked via dnsbl" in haystack
  )

  keyword_labels = [
    ("phishing", ["phishing", "credential", "login verification", "account suspended"]),
    ("malware", ["malware", "trojan", "ransomware", "exploit"]),
    ("ads", ["adserver", "advertising", "doubleclick", "ads.", "securepubads", "googlesyndication", "moatads"]),
    ("tracking", ["tracking", "tracker", "pixel tracker", "beacon"]),
    ("telemetry", ["telemetry", "metrics", "analytics", "crashlytics", "stats"]),
  ]
  for label, keywords in keyword_labels:
    if any(keyword in haystack for keyword in keywords):
      reason = f"heuristic keyword match for {label}"
      if already_blocked:
        reason += "; also already blocked by pfBlockerNG DNSBL"
      return Review(domain, label, "approve", 0.9 if already_blocked else 0.82, reason)

  if already_blocked:
    return Review(domain, "already-blocked", "reject", 0.99, "pfBlockerNG DNSBL block page without block keyword")

  if row.get("classification") == "suspicious" and row.get("reasons"):
    return Review(domain, "tracking", "approve", 0.72, "inspector classified as suspicious")

  provider_suffixes = ("amazonaws.com", "cloudfront.net", "azure.com", "googleusercontent.com", "scw.cloud")
  if domain.endswith(provider_suffixes):
    return Review(domain, "cloud-provider", "reject", 0.75, "generic provider infrastructure")

  return Review(domain, "unknown", "uncertain", 0.5, "not enough evidence")

def ai_review_batch(rows: list[dict[str, Any]], endpoint: str, model: str, api_key: str, timeout: int) -> list[Review]:
  payload = {
    "model": model,
    "temperature": 0,
    "response_format": {"type": "json_object"},
    "messages": [
      {
        "role": "system",
        "content": (
          "You classify domains for a personal pfBlockerNG DNS blocklist. "
          "Use only the supplied metadata/snippets. Do not assume unknown domains are bad. "
          "Return JSON: {\"reviews\":[{\"domain\":str,\"label\":str,\"decision\":\"approve|reject|uncertain\",\"confidence\":0..1,\"reason\":str}]}. "
          "Approve only clear ads, tracking, telemetry, malware, phishing, scam, or malvertising. "
          "Reject benign/cloud-provider/infrastructure/already-blocked. Mark weak evidence uncertain."
        ),
      },
      {"role": "user", "content": json.dumps([compact_evidence(row) for row in rows], ensure_ascii=False)},
    ],
  }
  request = urllib.request.Request(
    endpoint,
    data=json.dumps(payload).encode("utf-8"),
    headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
    method="POST",
  )
  with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - explicit user-configured AI endpoint
    data = json.loads(response.read().decode("utf-8"))
  content = data["choices"][0]["message"]["content"]
  parsed = json.loads(content)
  reviews: list[Review] = []
  by_domain = {row["domain"]: row for row in rows}
  for item in parsed.get("reviews", []):
    domain = str(item.get("domain", ""))
    if domain not in by_domain:
      continue
    decision = str(item.get("decision", "uncertain")).lower()
    if decision not in {"approve", "reject", "uncertain"}:
      decision = "uncertain"
    label = re.sub(r"[^a-z0-9_-]", "", str(item.get("label", "unknown")).lower()) or "unknown"
    confidence = float(item.get("confidence", 0.0))
    reason = str(item.get("reason", "")).strip()[:300]
    reviews.append(Review(domain, label, decision, max(0.0, min(1.0, confidence)), reason))
  reviewed_domains = {review.domain for review in reviews}
  for row in rows:
    if row["domain"] not in reviewed_domains:
      reviews.append(heuristic_review(row))
  return reviews

def batched(items: list[dict[str, Any]], size: int) -> list[list[dict[str, Any]]]:
  return [items[index : index + size] for index in range(0, len(items), size)]

def write_review_outputs(reviews: list[Review], output_dir: Path, min_confidence: float) -> None:
  output_dir.mkdir(parents=True, exist_ok=True)
  buckets = {
    "approved.txt": [],
    "rejected.txt": [],
    "uncertain.txt": [],
    "review.jsonl": [],
  }
  for review in reviews:
    approved = review.decision == "approve" and review.confidence >= min_confidence and review.label in BLOCK_LABELS
    rejected = review.decision == "reject" or review.label in SAFE_LABELS
    line = f"{review.domain} # label={review.label} confidence={review.confidence:.2f} reason={review.reason}"
    if approved:
      buckets["approved.txt"].append(line)
    elif rejected:
      buckets["rejected.txt"].append(line)
    else:
      buckets["uncertain.txt"].append(line)
    buckets["review.jsonl"].append(json.dumps(review.__dict__, sort_keys=True))

  for filename, lines in buckets.items():
    (output_dir / filename).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

def run(args: argparse.Namespace) -> int:
  rows = load_inspections(args.inspections, args.limit)
  api_key = os.environ.get(args.api_key_env)
  reviews: list[Review] = []
  if api_key and not args.no_ai:
    for batch in tqdm(batched(rows, args.batch_size), desc="AI reviewing", unit="batch"):
      try:
        reviews.extend(ai_review_batch(batch, args.endpoint, args.model, api_key, args.timeout))
      except (urllib.error.URLError, TimeoutError, OSError, KeyError, json.JSONDecodeError, ValueError) as exc:
        print(f"AI review failed for batch, falling back to heuristics: {exc}")
        reviews.extend(heuristic_review(row) for row in batch)
  else:
    reviews = [heuristic_review(row) for row in tqdm(rows, desc="Reviewing locally", unit="domain")]

  write_review_outputs(reviews, args.output_dir, args.min_confidence)
  approved = sum(1 for review in reviews if review.decision == "approve" and review.confidence >= args.min_confidence and review.label in BLOCK_LABELS)
  rejected = sum(1 for review in reviews if review.decision == "reject" or review.label in SAFE_LABELS)
  uncertain = len(reviews) - approved - rejected
  print(f"Reviewed: {len(reviews)}")
  print(f"Approved: {approved}")
  print(f"Rejected: {rejected}")
  print(f"Uncertain: {uncertain}")
  print(f"Output dir: {args.output_dir}")
  return 0

def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(description="Review inspected candidate domains with optional OpenAI-compatible AI classifier.")
  parser.add_argument("--inspections", type=Path, default=Path("reports/domain-inspection.jsonl"), help="JSONL generated by inspect-candidates.")
  parser.add_argument("--output-dir", type=Path, default=Path("reports/ai-review"), help="Directory for approved/rejected/uncertain outputs.")
  parser.add_argument("--limit", type=int, default=200, help="Maximum inspected domains to review.")
  parser.add_argument("--batch-size", type=int, default=20, help="AI review batch size.")
  parser.add_argument("--min-confidence", type=float, default=0.75, help="Minimum confidence for approved.txt.")
  parser.add_argument("--endpoint", default=os.environ.get("AI_REVIEW_ENDPOINT", DEFAULT_ENDPOINT), help="OpenAI-compatible chat completions endpoint.")
  parser.add_argument("--model", default=os.environ.get("AI_REVIEW_MODEL", DEFAULT_MODEL), help="OpenAI-compatible model name.")
  parser.add_argument("--api-key-env", default="AI_REVIEW_API_KEY", help="Environment variable containing API key.")
  parser.add_argument("--timeout", type=int, default=60, help="AI request timeout.")
  parser.add_argument("--no-ai", action="store_true", help="Force heuristic-only review.")
  return parser

def main(argv: list[str] | None = None) -> int:
  return run(build_parser().parse_args(argv))

if __name__ == "__main__":
  raise SystemExit(main())
