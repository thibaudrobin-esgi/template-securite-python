from unittest.mock import MagicMock, patch

from tp1.utils.lib import hello_world, choose_interface


def test_when_hello_world_then_return_hello_world():
    # Given
    string = "hello world"

    # When
    result = hello_world()

    # Then
    assert result == string


def test_when_no_interface_then_return_empty_string():
    # Given
    with patch("tp1.utils.lib.conf") as conf:
        conf.ifaces.values.return_value = []

        # When
        result = choose_interface()

    # Then
    assert result == ""


def test_when_choose_interface_then_return_name():
    # Given
    eth = MagicMock()
    eth.name = "Ethernet"
    wifi = MagicMock()
    wifi.name = "Wi-Fi"

    with patch("tp1.utils.lib.conf") as conf, patch("builtins.input", return_value="1"):
        conf.ifaces.values.return_value = [eth, wifi]

        # When
        result = choose_interface()

    # Then
    assert result == "Wi-Fi"


def test_when_bad_choice_then_ask_again():
    # Given
    eth = MagicMock()
    eth.name = "Ethernet"

    with patch("tp1.utils.lib.conf") as conf, patch("builtins.input", side_effect=["abc", "5", "0"]):
        conf.ifaces.values.return_value = [eth]

        # When
        result = choose_interface()

    # Then
    assert result == "Ethernet"
