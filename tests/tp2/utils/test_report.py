import json

from tp2.utils.report import Report


def test_generate_json(tmp_path):
    # Given
    data = {"sha256": "abc", "flag": "ESGI{x}", "iocs": {"domains": ["a.com"]}}
    out = tmp_path / "ech.bin.triage.json"

    # When
    Report(data).generate_json(str(out))

    # Then : le JSON relu est identique
    assert json.loads(out.read_text(encoding="utf-8")) == data
