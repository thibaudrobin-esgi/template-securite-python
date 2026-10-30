"""TP3 - Breach the target.

Enchaîne une phase web (fuzzing + CAPTCHA) et une phase réseau (décodage
chronométré). Voir tp3-breach-the-target.md.

    poetry run tp3 --target http://127.0.0.1:8080

Hypothèses sur le serveur (à ajuster quand il tourne) :
- le CAPTCHA est servi en image sur <target>/captcha ;
- après résolution, le serveur renvoie Flag 1 et la cible réseau de la
  phase 2 sous la forme "host:port" avec une clé "key=...".
"""

import argparse
import base64
import re
import time

from pwn import remote

from tp3.utils.config import logger
from tp3.utils.session import Session

CAPTCHA_PATH = "/captcha"
FLAG_RE = re.compile(r"[A-Za-z0-9_]*\{[^}]+\}")
HOSTPORT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}|[\w.-]+):(\d{2,5})")
KEY_RE = re.compile(r"key=([0-9a-fA-F]+)")
DEADLINE = 30


def xor(data: bytes, key: bytes) -> bytes:
    """XOR octet par octet avec une clé répétée."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def decode_line(line: bytes, key: bytes) -> bytes:
    """Décode une ligne base64 puis la déchiffre par XOR."""
    return xor(base64.b64decode(line), key)


def breach_web(target: str) -> tuple[str, int, bytes]:
    """Fuzz les endpoints, casse le CAPTCHA, retourne (host, port, key).

    Affiche aussi Flag 1. Indices : requests, PIL, pytesseract.
    """
    session = Session(target.rstrip("/") + CAPTCHA_PATH)
    session.prepare_request(flag="")
    session.submit_request()
    body = session.response.text

    flag1 = FLAG_RE.search(body)
    if flag1:
        logger.info(f"Flag 1: {flag1.group(0)}")

    hostport = HOSTPORT_RE.search(body)
    keymatch = KEY_RE.search(body)
    if not hostport or not keymatch:
        raise ValueError("host:port ou key introuvables dans la réponse web")

    host, port = hostport.group(1), int(hostport.group(2))
    key = bytes.fromhex(keymatch.group(1))
    return host, port, key


def breach_network(host: str, port: int, key: bytes) -> str:
    """pwntools/socket : décode le flux base64+XOR en boucle sous 30 s.

    Retourne le flag final. Indices : pwn.remote, base64.
    """
    io = remote(host, port)
    start = time.time()
    try:
        while time.time() - start < DEADLINE:
            line = io.recvline(timeout=DEADLINE)
            if not line:
                break
            clear = decode_line(line.strip(), key)
            logger.debug(f"déchiffré: {clear!r}")
            match = FLAG_RE.search(clear.decode(errors="ignore"))
            if match:
                return match.group(0)
    finally:
        io.close()
    raise TimeoutError("flag non trouvé dans le temps imparti")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:8080")
    args = ap.parse_args()

    logger.info("Starting TP3 - breach the target")
    host, port, key = breach_web(args.target)
    flag = breach_network(host, port, key)
    logger.info(f"FLAG_FINAL: {flag}")


if __name__ == "__main__":
    main()
