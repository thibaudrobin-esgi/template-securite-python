import io
import re

import pytesseract
import requests
from PIL import Image

WHITELIST = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


class Captcha:
    def __init__(self, url):
        self.url = url
        self.image = None
        self.value = ""

    def capture(self):
        """
        Télécharge l'image du captcha et la charge en mémoire.
        """
        resp = requests.get(self.url, timeout=10)
        resp.raise_for_status()
        self.image = Image.open(io.BytesIO(resp.content))

    def solve(self):
        """
        Résout le captcha par OCR après un prétraitement (niveaux de gris,
        agrandissement, binarisation) qui aide Tesseract.
        """
        if self.image is None:
            self.capture()

        image = self.image.convert("L")
        image = image.resize((image.width * 3, image.height * 3))
        image = image.point(lambda p: 0 if p < 140 else 255)

        config = f"--psm 7 -c tessedit_char_whitelist={WHITELIST}"
        text = pytesseract.image_to_string(image, config=config)
        self.value = re.sub(r"[^A-Za-z0-9]", "", text)
        return self.value

    def get_value(self):
        """
        Retourne la valeur résolue du captcha.
        """
        return self.value
