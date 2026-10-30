import re

import requests

from src.tp3.utils.captcha import Captcha

FLAG_RE = re.compile(r"[A-Za-z0-9_]*\{[^}]+\}")


class Session:
    """
    Class representing a session to solve a captcha and submit a flag.

    Attributes:
        url (str): The URL of the captcha.
        captcha_value (str): The value of the solved captcha.
        flag_value (str): The value of the flag to submit.
        valid_flag (str): The valid flag obtained after processing the response.
    """

    def __init__(self, url):
        """
        Initializes a new session with the given URL.

        Args:
            url (str): The URL of the captcha.
        """
        self.url = url
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""
        self.response = None

    def prepare_request(self, flag):
        """
        Prepares the request for sending by capturing and solving the captcha.
        """
        captcha = Captcha(self.url)
        captcha.capture()
        captcha.solve()

        self.captcha_value = captcha.get_value()
        self.flag_value = flag

    def submit_request(self):
        """
        Sends the flag and captcha.

        Hypothèse serveur : POST avec les champs `captcha` et `flag`. À ajuster
        selon les vrais noms de champs du challenge.
        """
        self.response = requests.post(
            self.url,
            data={"captcha": self.captcha_value, "flag": self.flag_value},
            timeout=10,
        )
        return self.response

    def process_response(self):
        """
        Processes the response and extracts a flag if present.
        """
        if self.response is None:
            return None

        match = FLAG_RE.search(self.response.text)
        if match:
            self.valid_flag = match.group(0)
        return self.valid_flag

    def get_flag(self):
        """
        Returns the valid flag.

        Returns:
            str: The valid flag.
        """
        return self.valid_flag
