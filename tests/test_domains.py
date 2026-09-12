from hosts_automation.domains import extract_domains, normalize_domain
from hosts_automation.discover_candidates import domains_from_log_line, score_domain

def test_normalize_domain_filters_ips_and_urls():
  assert normalize_domain("https://WWW.Example.com/path") == "example.com"
  assert normalize_domain("0.0.0.0") is None
  assert normalize_domain("localhost") is None

def test_extract_domains_supports_common_blocklist_formats():
  text = """
  # comment
  0.0.0.0 ads.example.com
  ||track.example.com^
  address=/metrics.example.com/0.0.0.0
  bad.example.net # inline comment
  """
  assert extract_domains(text) == {
    "ads.example.com",
    "track.example.com",
    "metrics.example.com",
    "bad.example.net",
  }

def test_domains_from_log_line_extracts_domains():
  line = "Sep 1 unbound query[A] telemetry.example.com from 192.0.2.10"
  assert "telemetry.example.com" in domains_from_log_line(line)

def test_score_domain_prefers_tracking_and_volume():
  score, reasons = score_domain("metrics.example.com", 25)
  assert score >= 15
  assert any("keywords" in reason for reason in reasons)
