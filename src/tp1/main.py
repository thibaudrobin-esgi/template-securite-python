import argparse
from pathlib import Path

from tp1.utils.analysis import analyse, blocking_rule, find_flag
from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report, build_summary


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="tp1", description="IDS maison : statistiques et detection d'attaques"
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--pcap", help="fichier PCAP a analyser")
    source.add_argument("--iface", help="interface a ecouter (developpement)")
    parser.add_argument("--out", default="report.json", help="rapport JSON (defaut : report.json)")
    parser.add_argument("--pdf", help="rapport PDF (defaut : report.pdf a cote du JSON)")
    parser.add_argument("--count", type=int, default=200, help="paquets a capturer en live")
    parser.add_argument("--timeout", type=int, default=30, help="duree max de la capture live (s)")
    return parser.parse_args(argv)


def main(argv=None) -> None:
    args = parse_args(argv)
    logger.info("Starting TP1")

    capture = Capture(pcap=args.pcap or "", interface=args.iface)
    capture.capture_traffic(count=args.count, timeout=args.timeout)
    logger.info("Protocoles :\n" + capture.get_all_protocols())

    attacks = analyse(capture.packets)
    flag = find_flag(capture.packets, attacks)
    for attack in attacks:
        logger.warning(f"{attack.type} depuis {attack.attacker} ({attack.detail}) -> {blocking_rule(attack)}")
    logger.info(f"Flag : {flag}")

    capture.summary = build_summary(capture, attacks, flag)
    json_path = Path(args.out)
    pdf_path = Path(args.pdf) if args.pdf else json_path.with_name("report.pdf")
    json_path.parent.mkdir(parents=True, exist_ok=True)

    report = Report(capture, str(pdf_path), capture.get_summary(), attacks, flag)
    report.save_json(str(json_path))
    logger.info(f"Rapport JSON : {json_path}")

    # le PDF ne doit pas empecher l'ecriture du JSON, qui est lu par la correction
    try:
        report.generate("graph")
        report.generate("array")
        report.save(str(pdf_path))
        logger.info(f"Rapport PDF : {pdf_path}")
    except Exception as erreur:
        logger.error(f"Echec de la generation du PDF : {erreur}")


if __name__ == "__main__":
    main()
