from __future__ import annotations

import argparse
import html.parser
import json
import re
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

from tqdm import tqdm

from hosts_automation.approve_candidates import parse_candidate_line
from hosts_automation.domains import normalize_domain

BAD_KEYWORDS = {
  "adserver",
  "advertising",
  "analytics",
  "beacon",
  "click tracker",
  "malware",
  "metrics",
  "phishing",
  "pixel tracker",
  "telemetry",
  "tracking",
}
MAX_BYTES = 128 * 1024

class TitleParser(html.parser.HTMLParser):
  def __init__(self) -> None:
    super().__init__()
    self.in_title = False
    self.title_parts: list[str] = []
    self.meta: dict[str, str] = {}

  def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
    if tag.lower() == "title":
      self.in_title = True
    if tag.lower() == "meta":
      attr_map = {key.lower(): value or "" for key, value in attrs}
      name = attr_map.get("name") or attr_map.get("property")
      content = attr_map.get("content")
      if name and content and name.lower() in {"description", "og:description", "generator"}:
        self.meta[name.lower()] = content.strip()[:300]

  def handle_endtag(self, tag: str) -> None:
    if tag.lower() == "title":
      self.in_title = False

  def handle_data(self, data: str) -> None:
    if self.in_title:
      self.title_parts.append(data)

  @property
  def title(self) -> str:
    return re.sub(r"\s+", " ", " ".join(self.title_parts)).strip()[:300]

@dataclass
class InspectionResult:
  domain: str
  url: str
  ok: bool
  error: str | None = None
  status: int | None = None
  final_url: str | None = None
  content_type: str | None = None
  server: str | None = None
  title: str | None = None
  meta: dict[str, str] | None = None
  snippet: str | None = None
  classification: str = "unknown"
  reasons: list[str] | None = None

def load_domains(path: Path, limit: int) -> list[str]:
  domains: list[str] = []
  for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
    if not line.strip() or line.startswith("#"):
      continue
    parsed = parse_candidate_line(line)
    domain = parsed[0] if parsed else normalize_domain(line.split()[0])
    if domain and domain not in domains:
      domains.append(domain)
    if len(domains) >= limit:
      break
  return domains

def load_completed_domains(path: Path) -> set[str]:
  completed: set[str] = set()
  if not path.exists():
    return completed
  for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
    if not line.strip():
      continue
    try:
      row = json.loads(line)
    except json.JSONDecodeError:
      continue
    domain = normalize_domain(str(row.get("domain", "")))
    if domain:
      completed.add(domain)
  return completed

def text_snippet(content: bytes, content_type: str | None) -> tuple[str | None, str | None, dict[str, str]]:
  if content_type and not any(kind in content_type.lower() for kind in ("html", "text", "json", "xml", "javascript")):
    return None, None, {}
  text = content.decode("utf-8", errors="ignore")
  parser = TitleParser()
  if "html" in (content_type or "").lower() or "<html" in text[:500].lower():
    parser.feed(text[:MAX_BYTES])
  stripped = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text)).strip()[:500]
  return parser.title or None, stripped or None, parser.meta

def classify(result: InspectionResult) -> tuple[str, list[str]]:
  haystack = " ".join(
    value
    for value in [result.domain, result.url, result.final_url or "", result.title or "", result.snippet or "", result.server or ""]
    if value
  ).lower()
  if "pfblockerng dnsbl" in haystack or "site blocked via dnsbl" in haystack:
    return "already-blocked", ["pfblockerng-dnsbl"]

  reasons: list[str] = []
  for keyword in sorted(BAD_KEYWORDS):
    if keyword in haystack:
      reasons.append(f"keyword:{keyword}")
  if result.status in {401, 403, 404} and any(word in result.domain for word in ("ads", "metrics", "telemetry", "track")):
    reasons.append(f"blocked-or-hidden-status:{result.status}")
  if reasons:
    return "suspicious", reasons
  if result.ok and result.status and 200 <= result.status < 400:
    return "reachable-unknown", []
  return "unknown", []

def fetch_url(url: str, timeout: int) -> InspectionResult:
  request = urllib.request.Request(
    url,
    headers={
      "User-Agent": "hosts-automation-inspector/0.1 (+no-js; security research)",
      "Accept": "text/html,text/plain,application/json,application/xml;q=0.9,*/*;q=0.1",
    },
  )
  domain = urllib.request.urlparse(url).hostname or url
  try:
    with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:  # noqa: S310 - explicit inspection command
      content = response.read(MAX_BYTES)
      content_type = response.headers.get("content-type")
      title, snippet, meta = text_snippet(content, content_type)
      result = InspectionResult(
        domain=domain,
        url=url,
        ok=True,
        status=response.status,
        final_url=response.url,
        content_type=content_type,
        server=response.headers.get("server"),
        title=title,
        meta=meta,
        snippet=snippet,
      )
  except (urllib.error.URLError, TimeoutError, socket.timeout, ssl.SSLError, OSError) as exc:
    result = InspectionResult(domain=domain, url=url, ok=False, error=str(exc))
  result.classification, result.reasons = classify(result)
  return result

def inspect_domain(domain: str, timeout: int) -> InspectionResult:
  https_result = fetch_url(f"https://{domain}/", timeout)
  if https_result.ok:
    return https_result
  return fetch_url(f"http://{domain}/", timeout)

def run(args: argparse.Namespace) -> int:
  domains = load_domains(args.candidates, args.limit)
  args.output.parent.mkdir(parents=True, exist_ok=True)
  completed = set() if args.no_resume else load_completed_domains(args.output)
  completed_in_selection = completed.intersection(domains)
  previous_outside_selection = completed - set(domains)
  pending = [domain for domain in domains if domain not in completed]
  if completed and not args.no_resume:
    print(
      f"Resuming: {len(completed_in_selection)} already inspected in current selection, "
      f"{len(pending)} pending, {len(previous_outside_selection)} previous outside current selection"
    )
  mode = "w" if args.no_resume else "a"
  with args.output.open(mode, encoding="utf-8") as output:
    for domain in tqdm(pending, desc="Inspecting domains", unit="domain"):
      result = inspect_domain(domain, args.timeout)
      output.write(json.dumps(asdict(result), sort_keys=True) + "\n")
      output.flush()
      tqdm.write(f"{domain}: {result.classification} {result.status or '-'} {','.join(result.reasons or [])}")
  print(f"Inspected this run: {len(pending)}")
  print(f"Output: {args.output}")
  return 0

def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(description="Safely fetch candidate domain metadata/content snippets without executing JavaScript.")
  parser.add_argument("--candidates", type=Path, default=Path("candidates.txt"), help="Candidate domains file.")
  parser.add_argument("--output", type=Path, default=Path("reports/domain-inspection.jsonl"), help="JSONL inspection report.")
  parser.add_argument("--limit", type=int, default=50, help="Maximum domains to inspect.")
  parser.add_argument("--timeout", type=int, default=5, help="HTTP timeout per request.")
  parser.add_argument("--no-resume", action="store_true", help="Overwrite output and inspect from the beginning.")
  return parser

def main(argv: list[str] | None = None) -> int:
  return run(build_parser().parse_args(argv))

if __name__ == "__main__":
  raise SystemExit(main())
