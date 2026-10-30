import json

from fpdf import FPDF

from tp1.utils.analysis import Attack, blocking_rule
from tp1.utils.capture import Capture

ATTACK_NAMES = {
    "arp_spoofing": "ARP spoofing",
    "port_scan": "Scan de ports",
    "sql_injection": "Injection SQL",
}


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str, attacks=None, flag=None):
        self.capture = capture
        self.filename = filename
        self.title = "Rapport d'analyse reseau"
        self.summary = summary
        self.attacks: list[Attack] = attacks or []
        self.flag = flag
        self.array = ""
        self.graph = ""

    def concat_report(self) -> str:
        """
        Concatenate report content
        """
        return self.title + self.summary + self.array + self.graph

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        protocols = self.capture.protocols
        if param == "graph":
            # le graphe est dessine dans save(), ici on garde juste le titre
            self.graph = "Paquets par protocole" if protocols else ""
        elif param == "array":
            array = f"{'Protocole':<25}{'Paquets':>8}\n"
            array += "-" * 33 + "\n"
            for nom, nb in protocols.items():
                array += f"{nom:<25}{nb:>8}\n"
            self.array = array

    def to_dict(self) -> dict:
        """
        Content of report.json
        """
        return {
            "protocols": dict(self.capture.protocols),
            "attacks": [{"type": a.type, "attacker": a.attacker} for a in self.attacks],
            "flag": self.flag,
        }

    def save_json(self, filename: str) -> None:
        with open(filename, "w", encoding="utf-8") as fichier:
            json.dump(self.to_dict(), fichier, indent=2)

    def save(self, filename: str) -> None:
        """
        Save report in a PDF file
        """
        pdf = FPDF()
        pdf.add_page()

        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, self.title, new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(5)

        pdf.set_font("Helvetica", size=11)
        pdf.multi_cell(0, 6, latin1(self.summary))
        pdf.ln(5)

        pdf.set_font("Courier", size=10)
        pdf.multi_cell(0, 5, latin1(self.array))
        pdf.ln(5)

        if self.graph:
            self._draw_graph(pdf)

        if self.attacks:
            self._draw_attacks(pdf)

        pdf.output(filename)

    def _draw_graph(self, pdf: FPDF) -> None:
        """
        Bar chart of the protocols, drawn with rectangles
        """
        protocols = self.capture.protocols
        maxi = max(protocols.values())

        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, self.graph, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", size=9)
        pdf.set_fill_color(70, 130, 180)

        for nom, nb in protocols.items():
            largeur = 110 * nb / maxi
            pdf.cell(48, 6, nom)
            pdf.rect(pdf.get_x(), pdf.get_y() + 1, largeur, 4, style="F")
            pdf.set_x(pdf.get_x() + largeur + 2)
            pdf.cell(0, 6, str(nb), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

    def _draw_attacks(self, pdf: FPDF) -> None:
        """
        Detected attacks with the suggested blocking rule
        """
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Attaques et regles de blocage proposees", new_x="LMARGIN", new_y="NEXT")
        for attack in self.attacks:
            pdf.set_font("Helvetica", "B", 10)
            titre = latin1(f"{ATTACK_NAMES[attack.type]} - {attack.attacker}")
            pdf.cell(0, 6, titre, new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", size=9)
            pdf.multi_cell(0, 5, latin1(attack.detail), new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Courier", size=9)
            pdf.multi_cell(0, 5, latin1(blocking_rule(attack)), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)


def latin1(text: str) -> str:
    """
    The core PDF fonts only support latin-1: replace the other characters
    """
    return text.encode("latin-1", errors="replace").decode("latin-1")


def build_summary(capture: Capture, attacks: list[Attack], flag: str | None) -> str:
    source = capture.pcap or f"interface {capture.interface}"
    summary = f"Source : {source}\n"
    summary += f"Paquets analyses : {len(capture.packets)}\n"
    if flag:
        summary += f"Flag : {flag}\n"
    summary += "\n"

    if not attacks:
        return summary + "Aucun trafic illegitime detecte, tout va bien."

    summary += f"{len(attacks)} attaque(s) detectee(s) :\n"
    for attack in attacks:
        summary += f"- {ATTACK_NAMES[attack.type]} depuis {attack.attacker}\n"
    return summary
