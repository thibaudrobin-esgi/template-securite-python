import argparse
from pathlib import Path

from tp2.utils.config import logger
from tp2.utils.report import Report
from tp2.utils.triage import Triage


def lister_fichiers(chemins):
    # fichiers ou dossiers -> liste a plat des fichiers a analyser
    fichiers = []
    for c in chemins:
        p = Path(c)
        if p.is_dir():
            fichiers += [f for f in sorted(p.iterdir()) if f.is_file()]
        elif p.is_file():
            fichiers.append(p)
        else:
            logger.warning(f"Chemin ignore (introuvable): {c}")
    return fichiers


def main():
    ap = argparse.ArgumentParser(description="TP2 - triage de malware")
    # le correcteur appelle : tp2 --samples /in/samples --rules /in/rules --out /out
    ap.add_argument("--samples", help="dossier (ou fichier) d'echantillons")
    ap.add_argument("--rules", help="dossier des regles YARA a utiliser")
    ap.add_argument("--out", help="dossier de sortie des rapports")
    # on garde aussi l'appel manuel : tp2 sample.bin  ou  tp2 -f sample.bin
    ap.add_argument("fichiers", nargs="*", help="echantillon(s) en positionnel")
    ap.add_argument("-f", "--file", action="append", default=[], help="echantillon a analyser")
    ap.add_argument("--llm", choices=["openrouter", "ollama"], default="openrouter")
    args = ap.parse_args()

    entrees = list(args.file) + list(args.fichiers)
    if args.samples:
        entrees.append(args.samples)
    cibles = lister_fichiers(entrees)
    if not cibles:
        ap.error("aucun echantillon (--samples, positionnel ou -f/--file)")

    out = Path(args.out) if args.out else None
    if out:
        out.mkdir(parents=True, exist_ok=True)

    for sample in cibles:
        try:
            result = Triage(str(sample), args.llm, rules=args.rules).run()
        except Exception as e:  # un echantillon qui plante ne doit pas casser les autres
            logger.error(f"Triage echoue pour {sample}: {e}")
            continue

        # <echantillon>.triage.json dans --out si fourni, sinon a cote du fichier
        nom = f"{sample.name}.triage.json"
        json_path = str(out / nom) if out else f"{sample}.triage.json"
        report = Report(result)
        report.generate_json(json_path)
        try:
            report.generate_pdf(json_path[:-5] + ".pdf")
        except Exception as e:
            logger.warning(f"PDF non genere pour {sample}: {e}")
        logger.info(f"Rapport ecrit: {json_path}")


if __name__ == "__main__":
    main()
