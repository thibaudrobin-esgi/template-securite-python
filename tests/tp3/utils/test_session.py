from src.tp3.utils.session import Session


class _FakeResponse:
    def __init__(self, text):
        self.text = text


def test_session_init():
    # Given
    url = "http://example.com/captcha"

    # When
    session = Session(url)

    # Then
    assert session.url == url
    assert session.captcha_value == ""
    assert session.flag_value == ""
    assert session.valid_flag == ""


def test_submit_request(monkeypatch):
    # Given
    session = Session("http://example.com/captcha")
    session.captcha_value = "AB12"
    session.flag_value = "flag{1}"
    sent = {}

    def fake_post(url, data, timeout):
        sent.update(data)
        return _FakeResponse("ok")

    monkeypatch.setattr("src.tp3.utils.session.requests.post", fake_post)

    # When
    session.submit_request()

    # Then
    assert sent == {"captcha": "AB12", "flag": "flag{1}"}


def test_process_response():
    # Given
    session = Session("http://example.com/captcha")
    session.response = _FakeResponse("Bravo, voici FLAG{found_it}")

    # When
    result = session.process_response()

    # Then
    assert result == "FLAG{found_it}"


def test_process_response_without_response():
    # Given
    session = Session("http://example.com/captcha")

    # When
    result = session.process_response()

    # Then
    assert result is None


def test_get_flag():
    # Given
    session = Session("http://example.com/captcha")
    session.valid_flag = "FLAG123"

    # When
    result = session.get_flag()

    # Then
    assert result == "FLAG123"
