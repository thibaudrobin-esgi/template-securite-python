import io

from PIL import Image

from src.tp3.utils.captcha import Captcha


def _png_bytes():
    buf = io.BytesIO()
    Image.new("RGB", (40, 16), "white").save(buf, "PNG")
    return buf.getvalue()


class _FakeResponse:
    def __init__(self, content):
        self.content = content

    def raise_for_status(self):
        return None


def test_captcha_init():
    # Given
    url = "http://example.com/captcha"

    # When
    captcha = Captcha(url)

    # Then
    assert captcha.url == url
    assert captcha.image is None
    assert captcha.value == ""


def test_capture(monkeypatch):
    # Given
    captcha = Captcha("http://example.com/captcha")
    monkeypatch.setattr(
        "src.tp3.utils.captcha.requests.get",
        lambda *a, **k: _FakeResponse(_png_bytes()),
    )

    # When
    captcha.capture()

    # Then
    assert captcha.image is not None


def test_solve(monkeypatch):
    # Given
    captcha = Captcha("http://example.com/captcha")
    captcha.image = Image.new("RGB", (40, 16), "white")
    monkeypatch.setattr(
        "src.tp3.utils.captcha.pytesseract.image_to_string",
        lambda *a, **k: "AB 12\n",
    )

    # When
    result = captcha.solve()

    # Then
    assert result == "AB12"
    assert captcha.value == "AB12"


def test_get_value():
    # Given
    captcha = Captcha("http://example.com/captcha")
    captcha.value = "TEST123"

    # When
    result = captcha.get_value()

    # Then
    assert result == "TEST123"
