from hosts_automation.apply_review import load_review_domains

def test_load_review_domains_reads_approved_lines(tmp_path):
  path = tmp_path / "approved.txt"
  path.write_text("ads.example.com # label=ads confidence=0.90\n# comment\n", encoding="utf-8")
  assert load_review_domains(path) == {"ads.example.com"}
