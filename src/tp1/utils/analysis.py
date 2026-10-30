import base64
import re
from dataclasses import dataclass
from urllib.parse import unquote_plus
from scapy.all import ARP, IP, TCP
from tp1.utils.capture import is_http_request, tcp_payload

SQLI = re.compile(r"'\s*(or|and)\s|\bor\s+\d+=\d+|union.+select|;\s*drop\s|sleep\(|information_schema|'\s*--")
FLAG = re.compile(rb"ESGI\{[^{}\s]+\}")

@dataclass(frozen=True)
class Attack:
    type: str
    attacker: str
    detail: str = ""

def is_sql_injection(data):
    txt = unquote_plus(unquote_plus(data.decode(errors="ignore"))).lower()
    return SQLI.search(txt) is not None

def detect_arp_spoofing(packets):
    mac_of, ips_of, bad = {}, {}, set()
    for p in packets:
        if ARP not in p or p[ARP].psrc == "0.0.0.0": continue
        ip, mac = p[ARP].psrc, p[ARP].hwsrc
        if mac_of.setdefault(ip, mac) != mac: bad.add(mac)  # l'ip a change de mac
        ips_of.setdefault(mac, set()).add(ip)
    bad |= {m for m, ips in ips_of.items() if len(ips) > 1}  # une mac qui se fait passer pour plusieurs ip
    return [Attack("arp_spoofing", m) for m in sorted(bad)]

def detect_port_scan(packets):
    ports = {}
    for p in packets:
        if IP in p and TCP in p and p[TCP].flags == "S":
            ports.setdefault(p[IP].src, set()).add(p[TCP].dport)
    return [Attack("port_scan", ip, f"{len(v)} ports") for ip, v in ports.items() if len(v) >= 10]

def detect_sql_injection(packets):
    ips = {p[IP].src for p in packets if IP in p and is_http_request(p) and is_sql_injection(tcp_payload(p))}
    return [Attack("sql_injection", ip) for ip in sorted(ips)]

def find_flags(data):
    texts = [data, unquote_plus(data.decode(errors="ignore")).encode()]
    for b in re.findall(rb"[A-Za-z0-9+/]{16,}={0,2}", data):
        try: texts.append(base64.b64decode(b + b"==="[:-len(b) % 4]))
        except ValueError: pass
    return list(dict.fromkeys(f.decode() for t in texts for f in FLAG.findall(t)))

def find_flag(packets, attacks):
    # le vrai flag vient d'un attaquant, le reste c'est des leurres
    attackers = {a.attacker for a in attacks}
    for p in packets:
        if IP in p and p[IP].src in attackers and (flags := find_flags(bytes(p))):
            return flags[0]
    return None

def blocking_rule(attack):
    if attack.type == "arp_spoofing":
        return f"iptables -A INPUT -m mac --mac-source {attack.attacker} -j DROP"
    return f"iptables -A INPUT -s {attack.attacker} -j DROP"

def analyse(packets):
    return detect_arp_spoofing(packets) + detect_port_scan(packets) + detect_sql_injection(packets)