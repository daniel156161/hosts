set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

pfsense_host := env("PFSENSE_HOST", "pfsense")
pfsense_user := env("PFSENSE_USER", "root")
log_dir := env("PFSENSE_LOG_DIR", "logs/pfsense")

# Show available recipes
_default:
  just --list

# Run tests
test:
  uv run pytest

# Update block.txt from configured feeds
update:
  uv run update-blocklist

# Copy pfSense DNS/pfBlockerNG logs into logs/pfsense/
fetch-logs:
  mkdir -p {{log_dir}}
  tmp_file="$(mktemp)"; \
  trap 'rm -f "$tmp_file"' EXIT; \
  ssh {{pfsense_user}}@{{pfsense_host}} 'for path in /var/log/resolver.log /var/log/dnsmasq.log; do [ -f "$path" ] && printf "%s\n" "$path"; done; if [ -d /var/log/pfblockerng ]; then find /var/log/pfblockerng -maxdepth 1 -type f; fi' > "$tmp_file"; \
  if [ ! -s "$tmp_file" ]; then echo "No logs found on pfSense"; exit 1; fi; \
  while IFS= read -r remote_path; do \
    echo "copying $remote_path"; \
    scp {{pfsense_user}}@{{pfsense_host}}:"$remote_path" {{log_dir}}/"$(basename "$remote_path")"; \
  done < "$tmp_file"

# Fetch logs, generate candidates, inspect content, AI/heuristic review, dry-run apply
smart-review: fetch-logs
  uv run discover-candidates {{log_dir}}/*
  uv run inspect-candidates
  uv run review-candidates
  uv run apply-review --dry-run

# Apply domains approved by smart-review to block.txt
apply-review:
  uv run apply-review

# Full local check
check:
  uv sync --dev
  uv run pytest
  uv run update-blocklist --output /tmp/hosts-block-check.txt
  wc -l /tmp/hosts-block-check.txt
