from hosts_automation.review_candidates import Review, heuristic_review, write_review_outputs

def test_heuristic_review_approves_tracking_content():
  review = heuristic_review({"domain": "collector.example.com", "title": "Analytics and telemetry", "snippet": "metrics endpoint"})
  assert review.decision == "approve"
  assert review.label == "telemetry"

def test_heuristic_review_rejects_cloud_provider():
  review = heuristic_review({"domain": "service.amazonaws.com", "title": None, "snippet": None})
  assert review.decision == "reject"
  assert review.label == "cloud-provider"

def test_heuristic_review_approves_already_blocked_with_keyword():
  review = heuristic_review({"domain": "ads.example.com", "classification": "already-blocked", "reasons": ["pfblockerng-dnsbl"]})
  assert review.decision == "approve"
  assert review.label == "ads"

def test_heuristic_review_rejects_already_blocked_without_keyword():
  review = heuristic_review({"domain": "blocked.example.com", "classification": "already-blocked", "reasons": ["pfblockerng-dnsbl"]})
  assert review.decision == "reject"
  assert review.label == "already-blocked"

def test_write_review_outputs_splits_buckets(tmp_path):
  write_review_outputs(
    [
      Review("ads.example.com", "ads", "approve", 0.9, "ad server"),
      Review("cdn.example.com", "cdn", "reject", 0.8, "cdn"),
      Review("unknown.example.com", "unknown", "uncertain", 0.5, "weak"),
    ],
    tmp_path,
    0.75,
  )
  assert "ads.example.com" in (tmp_path / "approved.txt").read_text(encoding="utf-8")
  assert "cdn.example.com" in (tmp_path / "rejected.txt").read_text(encoding="utf-8")
  assert "unknown.example.com" in (tmp_path / "uncertain.txt").read_text(encoding="utf-8")
