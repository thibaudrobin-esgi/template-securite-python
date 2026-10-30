import logging
import sys

logger = logging.getLogger("TP1")

# logs sur stderr uniquement : le programme doit pouvoir tourner dans un
# conteneur sans droit d'ecriture en dehors du fichier de sortie
if not logger.handlers:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
