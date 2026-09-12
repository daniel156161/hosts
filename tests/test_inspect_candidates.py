from hosts_automation.inspect_candidates import InspectionResult, classify, load_completed_domains, load_domains, text_snippet

def test_text_snippet_extracts_title_and_meta():
  title, snippet, meta = text_snippet(
    b"<html><head><title>Telemetry Endpoint</title><meta name='description' content='metrics collector'></head><body>Hello</body></html>",
    "text/html",
  )
  assert title == "Telemetry Endpoint"
  assert "Hello" in snippet
  assert meta["description"] == "metrics collector"

def test_classify_marks_keyword_content_suspicious():
  result = InspectionResult(domain="metrics.example.com", url="https://metrics.example.com/", ok=True, status=200, title="Analytics")
  classification, reasons = classify(result)
  assert classification == "suspicious"
  assert reasons

def test_classify_detects_pfblockerng_dnsbl_page():
  result = InspectionResult(
    domain="ads.example.com",
    url="http://ads.example.com/",
    ok=True,
    status=200,
    server="pfBlockerNG DNSBL",
    title="Site blocked via DNSBL",
    snippet="Site blocked via DNSBL body",
  )
  classification, reasons = classify(result)
  assert classification == "already-blocked"
  assert reasons == ["pfblockerng-dnsbl"]

def test_load_domains_supports_candidate_file(tmp_path):
  path = tmp_path / "candidates.txt"
  path.write_text("metrics.example.com # score=30 count=10 reasons=keywords=metrics\n", encoding="utf-8")
  assert load_domains(path, 10) == ["metrics.example.com"]

def test_load_completed_domains_ignores_broken_jsonl(tmp_path):
  path = tmp_path / "inspection.jsonl"
  path.write_text('{"domain":"metrics.example.com"}\nnot-json\n{"domain":"ads.example.com"}\n', encoding="utf-8")
  assert load_completed_domains(path) == {"metrics.example.com", "ads.example.com"}
