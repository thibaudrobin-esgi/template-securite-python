import hashlib

from tp2.utils.sample import Sample, is_domain


def _sample(tmp_path):
    data = (
        b"MZ\x90\x00"
        b"http://evil.example/stage2.bin\x00"
        b"evil-c2.com\x00"
        b"185.12.34.56\x00"
        b"Global\\InstallerMutex\x00"
        b"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
        b"ESGI{flag_de_test}\x00"
    )
    f = tmp_path / "echantillon.bin"
    f.write_bytes(data)
    return Sample(str(f)), data


def test_metadata(tmp_path):
    # Given
    sample, data = _sample(tmp_path)

    # When
    meta = sample.get_file_metadata()

    # Then
    assert meta["sha256"] == hashlib.sha256(data).hexdigest()
    assert meta["md5"] == hashlib.md5(data).hexdigest()
    assert meta["size"] == len(data)
    assert 0 <= meta["entropy"] <= 8


def test_extract_iocs(tmp_path):
    # Given
    sample, _ = _sample(tmp_path)

    # When
    iocs = sample.extract_iocs()

    # Then
    assert "evil-c2.com" in iocs["domains"]
    assert "185.12.34.56" in iocs["ips"]
    assert "http://evil.example/stage2.bin" in iocs["urls"]
    assert any("InstallerMutex" in m for m in iocs["mutex"])
    assert any("CurrentVersion" in r for r in iocs["registry"])


def test_extract_flag(tmp_path):
    # Given
    sample, _ = _sample(tmp_path)

    # When / Then
    assert sample.extract_flag() == "ESGI{flag_de_test}"


def test_is_domain():
    # un vrai domaine vs un nom de fichier
    assert is_domain("evil-c2.com") is True
    assert is_domain("payload.bin") is False
