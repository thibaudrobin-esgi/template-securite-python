from tp2.utils.triage import Triage, guess_family, resume_statique


def test_guess_family_downloader():
    iocs = {"urls": ["http://x"], "registry": []}
    assert guess_family(["suspicious_downloader"], iocs, []) == "downloader"


def test_guess_family_unknown():
    iocs = {"urls": [], "registry": []}
    assert guess_family([], iocs, []) == "unknown"


def test_resume_statique():
    # Given
    meta = {"entropy": 5.0}
    iocs = {"domains": [], "ips": [], "urls": []}

    # When
    resume = resume_statique(meta, iocs, [], "dropper")

    # Then
    assert isinstance(resume, str)
    assert "dropper" in resume


def test_run_schema(tmp_path, monkeypatch):
    # Given : un echantillon avec un flag, sans cle LLM -> resume statique
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    ech = tmp_path / "ech.bin"
    ech.write_bytes(b"MZ http://bad.tld ESGI{run_ok}")
    regles = tmp_path / "r.yar"
    regles.write_text('rule mz { strings: $a = "MZ" condition: $a }')

    # When
    result = Triage(str(ech), "openrouter", rules=str(regles)).run()

    # Then : le format attendu par le correcteur est bien produit
    attendu = ("sha256", "md5", "size", "type", "entropy", "iocs",
               "yara_matches", "family_guess", "llm_summary", "flag")
    for cle in attendu:
        assert cle in result
    assert result["flag"] == "ESGI{run_ok}"
    assert "mz" in result["yara_matches"]
    assert isinstance(result["llm_summary"], str)
