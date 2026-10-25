import json

from nettoolkit.cli import main


def test_subnet_text(capsys):
    assert main(["subnet", "192.168.1.0/24"]) == 0
    out = capsys.readouterr().out
    assert "255.255.255.0" in out
    assert "254" in out


def test_subnet_json(capsys):
    assert main(["subnet", "10.0.0.0/8", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["network"] == "10.0.0.0"


def test_subnet_split(capsys):
    assert main(["subnet", "192.168.1.0/24", "--split", "25"]) == 0
    out = capsys.readouterr().out
    assert "192.168.1.128/25" in out


def test_invalid_cidr_returns_error(capsys):
    assert main(["subnet", "not-an-ip"]) == 2
    assert "error" in capsys.readouterr().err
