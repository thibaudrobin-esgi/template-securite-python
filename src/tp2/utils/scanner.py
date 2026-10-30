from pathlib import Path

import yara

from tp2.utils.config import logger

# nos regles sont a la racine du depot ; on les garde en repli si le correcteur
# ne passe pas de dossier --rules
RACINE = Path(__file__).resolve().parents[3]
DEFAUT = RACINE / "rules" / "course_rules.yar"


def fichiers_regles(source):
    # source = dossier (--rules), fichier .yar, ou None
    if source:
        p = Path(source)
        if p.is_dir():
            return sorted(p.glob("*.yar")) + sorted(p.glob("*.yara"))
        if p.is_file():
            return [p]
    return [DEFAUT] if DEFAUT.is_file() else []


class YaraScanner:
    def __init__(self, source=None) -> None:
        self.rules = None
        fichiers = fichiers_regles(source)
        if not fichiers:
            logger.warning("Regles YARA introuvables")
            return
        try:
            # on compile tous les fichiers d'un coup (un namespace par fichier)
            self.rules = yara.compile(filepaths={f.stem: str(f) for f in fichiers})
            logger.info(f"Regles YARA chargees ({len(fichiers)} fichier(s))")
        except yara.Error as e:
            # un fichier casse ne doit pas tout faire planter : on compile un par un
            logger.warning(f"Compilation YARA groupee KO ({e}), fichier par fichier")
            self.rules = []
            for f in fichiers:
                try:
                    self.rules.append(yara.compile(filepath=str(f)))
                except yara.Error as e2:
                    logger.warning(f"Regle ignoree {f}: {e2}")

    def scan(self, data) -> list[str]:
        """
        Return the names of the YARA rules that matched
        """
        if not self.rules:
            return []
        if isinstance(self.rules, list):
            noms = []
            for r in self.rules:
                noms += [str(m.rule) for m in r.match(data=data)]
            return noms
        return [str(m.rule) for m in self.rules.match(data=data)]
