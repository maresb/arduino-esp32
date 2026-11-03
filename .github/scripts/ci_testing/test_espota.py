"""Host-side espota tests; run with python -m pytest on this file."""

import getpass
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import warnings

import pytest

ESPOTA_PATH = Path(__file__).resolve().parents[3] / "tools" / "espota.py"
SPEC = importlib.util.spec_from_file_location("espota", ESPOTA_PATH)
espota = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(espota)

PASSWORD = "  a'b\"$;\\& end  "


@pytest.fixture
def upload(tmp_path, monkeypatch):
    image = tmp_path / "firmware.bin"
    image.write_bytes(b"firmware fixture")
    connection = Mock()
    connection.recv.return_value = b"OK"
    listener = Mock()
    listener.accept.return_value = (connection, ("127.0.0.1", 1234))
    invitation = Mock(return_value=(True, "AUTH " + "a" * 64, None))
    authenticate = Mock(return_value=(True, None))
    prompt = Mock(return_value=PASSWORD)
    monkeypatch.setattr(espota, "create_socket", Mock(return_value=listener))
    monkeypatch.setattr(espota, "send_invitation_and_get_auth_challenge", invitation)
    monkeypatch.setattr(espota, "authenticate", authenticate)
    monkeypatch.setattr(getpass, "getpass", prompt)
    return SimpleNamespace(
        run=lambda *args: espota.main(["-i", "127.0.0.1", "-f", str(image), *args]),
        listener=listener,
        connection=connection,
        invitation=invitation,
        authenticate=authenticate,
        prompt=prompt,
    )


@pytest.mark.parametrize("nonce_length", [32, 64])
def test_missing_password_prompts_for_either_protocol(upload, nonce_length):
    upload.invitation.return_value = (True, "AUTH " + "a" * nonce_length, None)
    assert upload.run() == 0
    upload.prompt.assert_called_once()
    assert upload.authenticate.call_args.args[2] == PASSWORD
    assert upload.authenticate.call_args.kwargs["use_old_protocol"] == (nonce_length == 32)
    upload.connection.sendall.assert_called_once_with(b"firmware fixture")


@pytest.mark.parametrize("password", ["", PASSWORD, "-leading"])
def test_explicit_password_never_prompts(upload, password):
    assert upload.run("--auth=" + password) == 0
    upload.prompt.assert_not_called()
    assert upload.authenticate.call_args.args[2] == password


def test_unauthenticated_device_never_prompts(upload):
    upload.invitation.return_value = (True, "OK", None)
    assert upload.run() == 0
    upload.prompt.assert_not_called()
    upload.authenticate.assert_not_called()
    upload.connection.sendall.assert_called_once_with(b"firmware fixture")


def test_md5_fallback_reuses_prompted_password(upload):
    upload.authenticate.side_effect = [(False, "Authentication Failed"), (True, None)]
    assert upload.run() == 0
    upload.prompt.assert_called_once()
    calls = upload.authenticate.call_args_list
    assert len(calls) == 2
    assert [call.args[2] for call in calls] == [PASSWORD, PASSWORD]
    assert [call.kwargs["use_md5_password"] for call in calls] == [False, True]


def test_explicit_md5_target_can_prompt(upload):
    assert upload.run("--md5-target") == 0
    upload.prompt.assert_called_once()
    assert upload.authenticate.call_args.args[2] == PASSWORD
    assert upload.authenticate.call_args.kwargs["use_md5_password"] is True


@pytest.mark.parametrize("error", [EOFError, KeyboardInterrupt])
def test_cancelled_input_aborts_before_authentication(upload, error, caplog):
    upload.prompt.side_effect = error
    assert upload.run() == 1
    assert "Password input unavailable or cancelled" in caplog.text
    upload.authenticate.assert_not_called()
    upload.listener.accept.assert_not_called()
    upload.listener.close.assert_called_once()


def test_getpass_cannot_fall_back_to_echoed_input(upload, caplog):
    def warn_before_fallback(*args):
        warnings.warn("Can not control echo on the terminal.", getpass.GetPassWarning)
        pytest.fail("getpass must stop before falling back to visible input")

    upload.prompt.side_effect = warn_before_fallback
    assert upload.run() == 1
    assert "Use --auth" in caplog.text
    upload.authenticate.assert_not_called()
    upload.listener.accept.assert_not_called()
    upload.listener.close.assert_called_once()


def test_invalid_challenge_does_not_prompt(upload):
    upload.invitation.return_value = (True, "AUTH invalid", None)
    assert upload.run() == 1
    upload.prompt.assert_not_called()
    upload.authenticate.assert_not_called()


def test_failed_invitation_does_not_prompt(upload):
    upload.invitation.return_value = (False, None, "No response from the ESP")
    assert upload.run() == 1
    upload.prompt.assert_not_called()
    upload.authenticate.assert_not_called()
