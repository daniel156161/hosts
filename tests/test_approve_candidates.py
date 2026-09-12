from hosts_automation.approve_candidates import is_high_confidence, parse_candidate_line

def test_parse_candidate_line_extracts_reasons_and_keywords():
  parsed = parse_candidate_line("incoming.telemetry.example.com # score=35 count=100 reasons=keywords=telemetry,high-volume=100")
  assert parsed is not None
  domain, score, count, reasons = parsed
  assert domain == "incoming.telemetry.example.com"
  assert score == 35
  assert count == 100
  assert "telemetry" in reasons
  assert "high-volume" in reasons

def test_high_confidence_approves_telemetry_keyword():
  ok, reason = is_high_confidence("metrics.example.com", 30, 10, {"metrics", "repeated"}, 30, 5)
  assert ok is True
  assert reason == "telemetry-keyword"

def test_high_confidence_rejects_provider_infra_without_keyword():
  ok, reason = is_high_confidence("ec2-198-51-100-1.compute.amazonaws.com", 40, 20, {"random-looking-label"}, 30, 5)
  assert ok is False
  assert reason == "provider-infrastructure"

def test_high_confidence_rejects_structural_only():
  ok, reason = is_high_confidence("host-198-51-100-1.example.net", 35, 20, {"random-looking-label", "medium-volume"}, 30, 5)
  assert ok is False
  assert reason == "weak-heuristic-only"
