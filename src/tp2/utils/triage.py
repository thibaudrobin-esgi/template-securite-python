import json
import requests

from tp2.utils.config import logger
from tp2.utils.llm import LLMTriage
from tp2.utils.sample import Sample
from tp2.utils.scanner import YaraScanner


def guess_family(yara, iocs, imports):
    # petite heuristique : on devine la famille avec les regles YARA et les imports
    regles = " ".join(yara).lower()
    imps = " ".join(imports).lower()
    if "ransom" in regles or "cryptencrypt" in imps: return "ransomware"
    if "cred" in regles or "steal" in regles or "keylog" in regles: return "stealer"
    if "download" in regles or "urlmon" in imps or iocs["urls"]: return "downloader"
    if "inject" in regles or "createremotethread" in imps or "wsasocket" in imps: return "rat"
    if "persist" in regles or "run_key" in regles or iocs["registry"]: return "dropper"
    return "unknown"


def resume_statique(meta, iocs, yara, famille):
    # resume de secours quand le LLM ne repond pas (pas de cle / hors ligne)
    regles = ", ".join(yara) if yara else "aucune"
    return (f"Famille probable: {famille}. Entropie {meta['entropy']} (0-8). "
            f"{len(iocs['domains'])} domaine(s), {len(iocs['ips'])} IP, "
            f"{len(iocs['urls'])} URL. Regles YARA: {regles}.")


class Triage:
    def __init__(self, path: str, backend: str, rules=None) -> None:
        self.path = path
        self.backend = backend
        self.scanner = YaraScanner(rules)
        self.llm = LLMTriage(backend)

    def run(self) -> dict:
        sample = Sample(self.path)
        logger.info(f"Triage de {self.path} ({len(sample.data)} octets)")

        meta = sample.get_file_metadata()
        iocs = sample.extract_iocs()
        binaire = sample.parse_binary()
        yara = self.scanner.scan(sample.data)
        flag = sample.extract_flag()
        famille = guess_family(yara, iocs, binaire.get("imports", []))

        # on tente le LLM mais on ne bloque jamais dessus, sinon resume statique
        resume = resume_statique(meta, iocs, yara, famille)
        features = json.dumps({"meta": meta, "iocs": iocs, "yara": yara, "bin": binaire}, ensure_ascii=False)
        try:
            verdict = json.loads(self.llm.triage(features))
            resume = verdict.get("capacites") or verdict.get("famille") or resume
            if isinstance(resume, (list, dict)): resume = json.dumps(resume, ensure_ascii=False)
            if verdict.get("famille"): famille = str(verdict["famille"])
        except (requests.RequestException, ValueError, RuntimeError) as e:
            logger.warning(f"Verdict LLM indisponible, resume statique: {e}")

        # format attendu par le correcteur (cf. slide Format de sortie)
        return {
            "sha256": meta["sha256"],
            "md5": meta["md5"],
            "size": meta["size"],
            "type": meta["type"],
            "entropy": meta["entropy"],
            "iocs": iocs,
            "yara_matches": yara,
            "family_guess": famille,
            "llm_summary": resume,
            "flag": flag,
            "bin": binaire,
        }
