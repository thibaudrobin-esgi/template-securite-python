import json

from fpdf import FPDF
from fpdf.enums import XPos, YPos


class Report:
    def __init__(self, result: dict) -> None:
        self.result = result

    def generate_json(self, out_json: str) -> None:
        """
        Write the triage report as JSON (read by the grader)
        """
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(self.result, f, ensure_ascii=False, indent=2)

    def generate_pdf(self, out_pdf: str) -> None:
        """
        Human readable PDF report
        """
        r = self.result
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        self._ligne(pdf, "Rapport de triage malware")
        pdf.set_font("Helvetica", size=11)
        self._ligne(pdf, f"Flag: {r.get('flag') or 'non trouve'}")

        self._section(pdf, "Empreintes", [
            f"sha256: {r.get('sha256', '')}",
            f"md5: {r.get('md5', '')}",
            f"taille: {r.get('size', '')} octets",
            f"type: {r.get('type', '')}",
            f"entropie: {r.get('entropy', '')} (0-8)",
            f"famille probable: {r.get('family_guess', '')}",
        ])
        self._section(pdf, "Regles YARA", r.get("yara_matches") or ["aucune"])

        iocs = r.get("iocs", {})
        lignes = [f"{k}: {', '.join(v) if v else 'aucun'}" for k, v in iocs.items()]
        self._section(pdf, "IOC", lignes or ["aucun"])

        binaire = r.get("bin", {})
        if binaire:
            self._section(pdf, "Analyse binaire", [
                f"format: {binaire.get('format')}",
                f"sections: {', '.join(binaire.get('sections', []))}",
                f"imports: {len(binaire.get('imports', []))}",
            ])
        self._section(pdf, "Resume LLM", [r.get("llm_summary", "non disponible")])
        pdf.output(out_pdf)

    def _section(self, pdf, titre, lignes):
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 13)
        self._ligne(pdf, titre)
        pdf.set_font("Helvetica", size=10)
        for ligne in lignes:
            self._ligne(pdf, ligne)

    def _ligne(self, pdf, texte):
        # fpdf2 ne gere que le latin-1 avec les polices de base, on nettoie
        safe = str(texte).encode("latin-1", "replace").decode("latin-1")
        # new_x/new_y : on repart a la marge gauche sinon la cellule suivante
        # a une largeur nulle et fpdf2 plante
        pdf.multi_cell(0, 7, safe, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
