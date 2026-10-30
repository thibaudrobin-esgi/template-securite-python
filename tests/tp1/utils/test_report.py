import json
from unittest.mock import MagicMock

from tp1.utils.analysis import Attack
from tp1.utils.report import Report, build_summary

ATTAQUES = [Attack("port_scan", "10.0.0.5", "20 ports sondes"), Attack("arp_spoofing", "aa:bb:cc:dd:ee:ff")]


def fausse_capture():
    capture = MagicMock()
    capture.protocols = {"TCP": 5, "UDP": 2}
    capture.packets = [None] * 7
    capture.pcap = "trace.pcap"
    return capture


def test_report_init():
    # Given
    capture = MagicMock()

    # When
    report = Report(capture, "test.pdf", "Test summary")

    # Then
    assert report.capture == capture
    assert report.filename == "test.pdf"
    assert report.title == "Rapport d'analyse reseau"
    assert report.summary == "Test summary"
    assert report.attacks == []
    assert report.flag is None
    assert report.array == ""
    assert report.graph == ""


def test_concat_report():
    # Given
    report = Report(MagicMock(), "test.pdf", "Test summary")
    report.title = "Test Title"
    report.array = "Test Array"
    report.graph = "Test Graph"

    # When
    result = report.concat_report()

    # Then
    assert result == "Test TitleTest summaryTest ArrayTest Graph"


def test_generate_graph():
    # Given
    report = Report(fausse_capture(), "test.pdf", "Test summary")

    # When
    report.generate("graph")

    # Then
    assert report.graph == "Paquets par protocole"


def test_generate_graph_without_packets():
    # Given
    capture = MagicMock()
    capture.protocols = {}
    report = Report(capture, "test.pdf", "Test summary")

    # When
    report.generate("graph")

    # Then
    assert report.graph == ""


def test_generate_array():
    # Given
    report = Report(fausse_capture(), "test.pdf", "Test summary")

    # When
    report.generate("array")

    # Then
    assert "TCP" in report.array
    assert "UDP" in report.array


def test_generate_invalid_param():
    # Given
    report = Report(fausse_capture(), "test.pdf", "Test summary")

    # When
    report.generate("invalid")

    # Then
    assert report.graph == ""
    assert report.array == ""


def test_save_pdf(tmp_path):
    # Given
    report = Report(fausse_capture(), "test.pdf", "Test summary", ATTAQUES, "ESGI{test}")
    report.generate("array")
    report.generate("graph")
    fichier = tmp_path / "test.pdf"

    # When
    report.save(str(fichier))

    # Then
    assert fichier.read_bytes().startswith(b"%PDF")


def test_save_json(tmp_path):
    # Given
    report = Report(fausse_capture(), "test.pdf", "Test summary", ATTAQUES, "ESGI{test}")
    fichier = tmp_path / "report.json"

    # When
    report.save_json(str(fichier))

    # Then
    assert json.loads(fichier.read_text()) == {
        "protocols": {"TCP": 5, "UDP": 2},
        "attacks": [
            {"type": "port_scan", "attacker": "10.0.0.5"},
            {"type": "arp_spoofing", "attacker": "aa:bb:cc:dd:ee:ff"},
        ],
        "flag": "ESGI{test}",
    }


def test_build_summary():
    assert "tout va bien" in build_summary(fausse_capture(), [], None)
    summary = build_summary(fausse_capture(), ATTAQUES, "ESGI{test}")
    assert "Scan de ports depuis 10.0.0.5" in summary
    assert "ESGI{test}" in summary
