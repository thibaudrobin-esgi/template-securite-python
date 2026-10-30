from tp2.utils.scanner import YaraScanner

REGLE = """rule trouve_mz
{
    strings:
        $mz = "MZ"
    condition:
        $mz
}
"""


def test_scan_match(tmp_path):
    # Given
    f = tmp_path / "regles.yar"
    f.write_text(REGLE)
    scanner = YaraScanner(str(f))

    # When
    matches = scanner.scan(b"MZ\x90\x00 hello")

    # Then
    assert "trouve_mz" in matches


def test_scan_no_match(tmp_path):
    # Given
    f = tmp_path / "regles.yar"
    f.write_text(REGLE)
    scanner = YaraScanner(str(f))

    # When / Then
    assert scanner.scan(b"rien ici") == []


def test_rules_from_directory(tmp_path):
    # Given : on passe un DOSSIER de regles (cas du correcteur avec --rules)
    (tmp_path / "a.yar").write_text(REGLE)
    scanner = YaraScanner(str(tmp_path))

    # When / Then
    assert "trouve_mz" in scanner.scan(b"MZ data")
