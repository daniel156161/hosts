from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}\.?$", re.IGNORECASE)
COMMENT_MARKERS = ("#", "!", "//")
HOSTS_IPS = {"0.0.0.0", "127.0.0.1", "::1"}

def strip_inline_comment(line: str) -> str:
  value = line.strip()
  for marker in COMMENT_MARKERS:
    index = value.find(marker)
    if index == 0:
      return ""
    if index > 0 and value[index - 1].isspace():
      value = value[:index].strip()
  return value

def normalize_domain(value: str) -> str | None:
  value = value.strip().lower().strip("'\"[](),;")
  if not value:
    return None

  if "://" in value:
    parsed = urlparse(value)
    value = parsed.hostname or ""
  elif value.startswith("||"):
    value = value[2:].split("^", 1)[0].split("/", 1)[0]
  elif value.startswith("."):
    value = value[1:]

  value = value.rstrip(".")
  if value.startswith("*."):
    value = value[2:]
  if value.startswith("www."):
    # Keep explicit www entries if they are in an existing local list, but feeds
    # and logs are cleaner when canonicalized to the registered hostname shape.
    value = value[4:]

  if not value or "/" in value or "@" in value or "*" in value:
    return None
  try:
    ipaddress.ip_address(value)
    return None
  except ValueError:
    pass
  if value in HOSTS_IPS or "." not in value:
    return None
  if not DOMAIN_RE.match(value):
    return None
  return value

def extract_domains(text: str) -> set[str]:
  domains: set[str] = set()
  for raw_line in text.splitlines():
    line = strip_inline_comment(raw_line)
    if not line:
      continue
    tokens = re.split(r"[\s,]+", line)
    if not tokens:
      continue

    # Hosts format: 0.0.0.0 bad.example
    if tokens[0] in HOSTS_IPS and len(tokens) > 1:
      candidates = tokens[1:]
    # dnsmasq/address format: address=/bad.example/0.0.0.0
    elif line.startswith("address=/"):
      candidates = [line.split("/", 2)[1]]
    else:
      candidates = tokens

    for candidate in candidates:
      domain = normalize_domain(candidate)
      if domain:
        domains.add(domain)
  return domains

def read_domain_file(path) -> set[str]:
  try:
    return extract_domains(path.read_text(encoding="utf-8", errors="ignore"))
  except FileNotFoundError:
    return set()
