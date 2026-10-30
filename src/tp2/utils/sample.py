import hashlib
import math
import re
from collections import Counter

import lief
import magic

# chaines ASCII imprimables du fichier -> on cherche les IOC dedans
STRINGS = re.compile(rb"[\x20-\x7e]{4,}")
URL = re.compile(r"https?://[^\s\"'<>]+")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
MUTEX = re.compile(r"(?:Global|Local)\\[^\s\"']+")
REGISTRY = re.compile(r"(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\s\"']+")
FLAG = re.compile(r"ESGI\{[^{}\s]+\}")

# extensions courantes -> pour ne pas prendre cmd.exe ou payload.bin pour un domaine
EXTENSIONS = {
    "exe", "dll", "bin", "dat", "sys", "txt", "log", "tmp", "png", "jpg",
    "gif", "json", "pdf", "zip", "ps1", "vbs", "bat", "scr", "ini", "cfg",
}


def is_domain(mot: str) -> bool:
    return mot.rsplit(".", 1)[-1].lower() not in EXTENSIONS


class Sample:
    def __init__(self, path: str) -> None:
        self.path = path
        self.data = open(path, "rb").read()
        # on garde les strings, elles resservent pour les IOC et le flag
        self.strings = [s.decode("ascii") for s in STRINGS.findall(self.data)]

    def shannon_entropy(self) -> float:
        """
        Shannon entropy of the bytes, between 0 and 8 (close to 8 = packed/encrypted)
        """
        if not self.data:
            return 0.0
        freq = Counter(self.data)
        n = len(self.data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def get_file_metadata(self) -> dict:
        """
        sha256, md5, size, file type (magic) and entropy
        """
        return {
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "md5": hashlib.md5(self.data).hexdigest(),
            "size": len(self.data),
            "type": magic.from_buffer(self.data),
            "entropy": round(self.shannon_entropy(), 3),
        }

    def extract_iocs(self) -> dict:
        """
        Extract IOC from the strings: domains, ips, urls, mutex, registry keys
        """
        blob = "\n".join(self.strings)
        # un domaine ne doit etre ni une ip ni un nom de fichier
        domaines = [d for d in DOMAIN.findall(blob) if not IPV4.fullmatch(d) and is_domain(d)]
        return {
            "domains": sorted(set(domaines)),
            "ips": sorted(set(IPV4.findall(blob))),
            "urls": sorted(set(URL.findall(blob))),
            "mutex": sorted(set(MUTEX.findall(blob))),
            "registry": sorted(set(REGISTRY.findall(blob))),
        }

    def extract_flag(self):
        # le flag est cache dans les strings de l'echantillon (ESGI{...})
        m = FLAG.search("\n".join(self.strings))
        return m.group(0) if m else None

    def parse_binary(self) -> dict:
        """
        imports and sections via lief (empty dict if not a PE/ELF)
        """
        binaire = lief.parse(self.path)
        if binaire is None:
            return {}
        return {
            "format": str(binaire.format).split(".")[-1],
            "sections": [s.name for s in binaire.sections],
            "libraries": list(binaire.libraries),
            "imports": [f.name for f in binaire.imported_functions][:200],
        }
