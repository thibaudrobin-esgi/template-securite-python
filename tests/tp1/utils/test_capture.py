from unittest.mock import patch

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap

from tp1.utils.capture import Capture, get_protocols, is_http, is_http_request


def test_capture_init_with_pcap_does_not_ask_interface():
    # Given
    with patch("tp1.utils.capture.choose_interface") as choose:
        # When
        capture = Capture(pcap="trace.pcap")

    # Then
    choose.assert_not_called()
    assert capture.pcap == "trace.pcap"
    assert capture.summary == ""


def test_capture_init_without_source_asks_interface():
    # Given
    with patch("tp1.utils.capture.choose_interface", return_value="eth0"):
        # When
        capture = Capture()

    # Then
    assert capture.interface == "eth0"


def test_capture_traffic_reads_pcap(tmp_path):
    # Given
    fichier = tmp_path / "trace.pcap"
    wrpcap(str(fichier), [Ether() / IP() / TCP(), Ether() / ARP()])
    capture = Capture(pcap=str(fichier))

    # When
    capture.capture_traffic()

    # Then
    assert len(capture.packets) == 2


def test_capture_traffic_live_uses_sniff():
    # Given
    capture = Capture(interface="eth0")

    # When
    with patch("tp1.utils.capture.sniff", return_value=[Ether()]) as sniff:
        capture.capture_traffic(count=5, timeout=1)

    # Then
    sniff.assert_called_once_with(iface="eth0", count=5, timeout=1)
    assert len(capture.packets) == 1


def test_capture_traffic_without_source():
    # Given
    capture = Capture(interface="")

    # When
    capture.capture_traffic()

    # Then
    assert capture.packets == []


def test_get_protocols_counts_every_layer():
    # Given
    requete = Ether() / IP() / TCP(dport=80) / Raw(b"GET / HTTP/1.1\r\n\r\n")

    # When
    result = get_protocols(requete)

    # Then
    assert result == ["Ethernet", "IP", "TCP", "HTTP"]


def test_get_protocols_dns_and_icmp():
    dns = Ether() / IP() / UDP() / DNS(qd=DNSQR(qname="a.test"))
    assert get_protocols(dns) == ["Ethernet", "IP", "UDP", "DNS"]
    assert get_protocols(Ether() / IP() / ICMP()) == ["Ethernet", "IP", "ICMP"]


def test_is_http():
    assert is_http_request(Ether() / IP() / TCP() / Raw(b"POST /login HTTP/1.1\r\n"))
    assert is_http(Ether() / IP() / TCP() / Raw(b"HTTP/1.1 200 OK\r\n"))
    assert not is_http_request(Ether() / IP() / TCP() / Raw(b"HTTP/1.1 200 OK\r\n"))
    assert not is_http(Ether() / IP() / TCP(dport=80))


def test_get_all_protocols_sorted():
    # Given
    capture = Capture(interface="")
    capture.packets = [Ether() / IP() / TCP(), Ether() / IP() / TCP(), Ether() / ARP()]

    # When
    result = capture.get_all_protocols()

    # Then
    assert capture.protocols == {"Ethernet": 3, "IP": 2, "TCP": 2, "ARP": 1}
    assert list(capture.protocols)[0] == "Ethernet"
    assert result.endswith("Total: 3")


def test_sort_network_protocols():
    # Given
    capture = Capture(interface="")
    capture.protocols = {"TCP": 5, "UDP": 2, "ARP": 1}

    # When
    result = capture.sort_network_protocols()

    # Then
    assert result == "TCP, UDP, ARP"


def test_get_summary():
    # Given
    capture = Capture(interface="")
    capture.summary = "Test summary"

    # When
    result = capture.get_summary()

    # Then
    assert result == "Test summary"
