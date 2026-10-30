import json

from scapy.all import ARP, IP, TCP, Ether, Raw, wrpcap

from tp1.main import main, parse_args


def test_parse_args():
    args = parse_args(["--pcap", "trace.pcap", "--out", "out.json"])
    assert args.pcap == "trace.pcap"
    assert args.out == "out.json"
    assert args.iface is None


def test_main_writes_json_and_pdf(tmp_path):
    # Given : une capture avec les trois attaques et le flag dans la requete de l'attaquant
    paquets = [Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="02:00:00:00:00:01", pdst="10.0.0.2")]
    paquets += [Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="02:00:00:00:00:66", pdst="10.0.0.2")]
    paquets += [Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=p, flags="S") for p in range(1, 30)]
    paquets += [
        Ether()
        / IP(src="10.0.0.9", dst="10.0.0.1")
        / TCP(dport=80, flags="PA")
        / Raw(b"GET /login?user=admin'%20OR%201=1--&t=ESGI{flag_test} HTTP/1.1\r\n\r\n")
    ]
    pcap = tmp_path / "trace.pcap"
    wrpcap(str(pcap), paquets)
    sortie = tmp_path / "report.json"

    # When
    main(["--pcap", str(pcap), "--out", str(sortie)])

    # Then
    rapport = json.loads(sortie.read_text())
    assert rapport["protocols"]["TCP"] == 30
    assert rapport["protocols"]["ARP"] == 2
    assert rapport["protocols"]["HTTP"] == 1
    assert {(a["type"], a["attacker"]) for a in rapport["attacks"]} == {
        ("arp_spoofing", "02:00:00:00:00:66"),
        ("port_scan", "10.0.0.5"),
        ("sql_injection", "10.0.0.9"),
    }
    assert rapport["flag"] == "ESGI{flag_test}"
    assert (tmp_path / "report.pdf").read_bytes().startswith(b"%PDF")
