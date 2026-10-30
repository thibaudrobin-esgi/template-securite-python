from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, IPv6, Raw, rdpcap, sniff

from tp1.utils.config import logger
from tp1.utils.lib import choose_interface

HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
)

# nom affiche -> couche scapy
LAYERS = {
    "Ethernet": Ether,
    "ARP": ARP,
    "IP": IP,
    "IPv6": IPv6,
    "TCP": TCP,
    "UDP": UDP,
    "ICMP": ICMP,
    "DNS": DNS,
}


def tcp_payload(packet) -> bytes:
    """
    Return the TCP payload of a packet (empty if none)
    """
    if TCP not in packet or Raw not in packet:
        return b""
    return bytes(packet[Raw].load)


def is_http_request(packet) -> bool:
    return tcp_payload(packet).startswith(HTTP_METHODS)


def is_http(packet) -> bool:
    """
    HTTP is recognised by its content, not by its port
    """
    payload = tcp_payload(packet)
    return payload.startswith(HTTP_METHODS) or payload.startswith(b"HTTP/")


def get_protocols(packet) -> list[str]:
    """
    Return every known protocol found in a packet (a HTTP packet is also TCP, IP and Ethernet)
    """
    protocols = [nom for nom, layer in LAYERS.items() if layer in packet]
    if is_http(packet):
        protocols.append("HTTP")
    return protocols


class Capture:
    def __init__(self, pcap: str = "", interface: str | None = None) -> None:
        self.pcap = pcap
        # l'interface n'est demandee que pour une capture live sans --iface
        self.interface = interface if interface is not None or pcap else choose_interface()
        self.summary = ""
        self.packets = []
        self.protocols = {}

    def capture_traffic(self, count: int = 200, timeout: int = 30) -> None:
        """
        Read the pcap file, or capture network traffic from an interface
        """
        if self.pcap:
            logger.info(f"Lecture du fichier {self.pcap}")
            self.packets = list(rdpcap(self.pcap))
        elif self.interface:
            logger.info(f"Capture sur l'interface {self.interface}")
            self.packets = list(sniff(iface=self.interface, count=count, timeout=timeout))
        else:
            logger.warning("Ni fichier ni interface, capture annulee")
            self.packets = []
        logger.info(f"{len(self.packets)} paquets lus")

    def get_all_protocols(self) -> str:
        """
        Count packets per protocol, sorted by volume
        """
        compteur = {}
        for packet in self.packets:
            for nom in get_protocols(packet):
                compteur[nom] = compteur.get(nom, 0) + 1
        self.protocols = dict(sorted(compteur.items(), key=lambda p: p[1], reverse=True))

        lignes = [f"{nom}: {nb}" for nom, nb in self.protocols.items()]
        lignes.append(f"Total: {len(self.packets)}")
        return "\n".join(lignes)

    def sort_network_protocols(self) -> str:
        """
        Return the protocols names, most used first
        """
        return ", ".join(self.protocols)

    def get_summary(self) -> str:
        return self.summary
