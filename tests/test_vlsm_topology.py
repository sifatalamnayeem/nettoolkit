import json
import os
import shutil
import tempfile

import pytest

from nettoolkit.cli import main
from nettoolkit.topology import build_dot, dot_escape, load_hosts, load_scans
from nettoolkit.vlsm import parse_requirement, plan_vlsm
from nettoolkit.vlsm.planner import block_size


# ---- vlsm -----------------------------------------------------------------

def test_classic_example():
    plan = plan_vlsm("192.168.10.0/24", [("HR", 10), ("Sales", 50), ("Link", 2), ("IT", 20)])
    got = [(a.name, f"{a.network}/{a.prefix}", a.first_host, a.last_host, a.usable) for a in plan.allocations]
    assert got == [
        ("Sales", "192.168.10.0/26", "192.168.10.1", "192.168.10.62", 62),
        ("IT", "192.168.10.64/27", "192.168.10.65", "192.168.10.94", 30),
        ("HR", "192.168.10.96/28", "192.168.10.97", "192.168.10.110", 14),
        ("Link", "192.168.10.112/30", "192.168.10.113", "192.168.10.114", 2),
    ]
    assert plan.free_blocks == ["192.168.10.116/30", "192.168.10.120/29", "192.168.10.128/25"]
    assert plan.used_addresses == 116 and plan.utilisation == 45.3
    assert [a.spare for a in plan.allocations] == [12, 10, 4, 0]


def test_block_sizes_at_the_edges():
    assert [block_size(n) for n in (1, 2, 3, 6, 7, 14, 15, 62, 63)] == [4, 4, 8, 8, 16, 16, 32, 64, 128]


def test_subnets_never_overlap_and_stay_inside_the_block():
    import ipaddress, random
    rng = random.Random(5)
    for _ in range(200):
        reqs = [(f"d{i}", rng.randrange(1, 60)) for i in range(rng.randrange(1, 8))]
        try:
            plan = plan_vlsm("10.0.0.0/22", reqs)
        except ValueError:
            continue
        nets = [ipaddress.ip_network(f"{a.network}/{a.prefix}") for a in plan.allocations]
        base = ipaddress.ip_network("10.0.0.0/22")
        assert all(n.subnet_of(base) for n in nets)
        assert not any(a.overlaps(b) for i, a in enumerate(nets) for b in nets[i + 1:])
        assert all(a.requested <= a.usable for a in plan.allocations)


def test_too_big_for_the_block():
    with pytest.raises(ValueError) as err:
        plan_vlsm("192.168.1.0/26", [("A", 50), ("B", 20)])
    assert "bigger block" in str(err.value)


def test_exact_fit_leaves_no_free_space():
    plan = plan_vlsm("192.168.1.0/24", [("A", 126), ("B", 126)])
    assert plan.free_blocks == [] and plan.utilisation == 100.0


def test_requirement_parsing_and_validation():
    assert parse_requirement("  Head   Office : 40") == ("Head Office", 40)
    for bad in ("Sales", "Sales:", ":5", "Sales:abc", "Sales:0", "Sales:-3", f"Sales:{2**30}"):
        with pytest.raises(ValueError):
            parse_requirement(bad)
    with pytest.raises(ValueError):
        plan_vlsm("192.168.1.0/24", [("A", 5), ("a", 5)])           # names are case-insensitive unique
    with pytest.raises(ValueError):
        plan_vlsm("2001:db8::/48", [("A", 5)])


def test_cli_vlsm(capsys):
    assert main(["vlsm", "192.168.10.0/24", "-r", "Sales:50", "-r", "IT:20"]) == 0
    out = capsys.readouterr().out
    assert "192.168.10.0/26" in out and "Free space:" in out
    assert main(["vlsm", "192.168.10.0/24", "-r", "Sales:50", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["allocations"][0]["prefix"] == 26
    assert main(["vlsm", "192.168.10.0/28", "-r", "Sales:50"]) == 2
    assert "bigger block" in capsys.readouterr().err


# ---- topology -------------------------------------------------------------

HOSTS = [{"ip": "192.168.1.20", "hostname": "laptop.lan"}, {"ip": "192.168.1.1", "hostname": "router.lan"},
         {"ip": "192.168.1.5", "hostname": ""}]


def test_dot_structure_and_ordering():
    dot = build_dot(HOSTS)
    assert dot.startswith("graph network {") and dot.rstrip().endswith("}")
    assert dot.index('"192.168.1.1" [') < dot.index('"192.168.1.5" [') < dot.index('"192.168.1.20" [')
    assert 'internet -- "192.168.1.1"' in dot and '"192.168.1.1" -- lan' in dot
    assert 'lan -- "192.168.1.20"' in dot and 'lan -- "192.168.1.1"' not in dot
    assert "Gateway" in dot


def test_open_ports_are_shown():
    scans = {"192.168.1.5": [{"port": 22, "open": True, "service": "ssh"}, {"port": 80, "open": True, "service": "http"}]}
    dot = build_dot(HOSTS, scans)
    assert "open: 22/ssh, 80/http" in dot


def test_explicit_gateway_not_in_scan_results():
    dot = build_dot([{"ip": "10.0.0.7", "hostname": ""}], gateway="10.0.0.254")
    assert '"10.0.0.254" [label="10.0.0.254\\nGateway"' in dot


def test_hostile_hostnames_cannot_inject_graph_syntax():
    evil = 'x"]; evil [label="pwned"]; "y\nsecond line \x1b[31m \\'
    dot = build_dot([{"ip": "10.0.0.2", "hostname": evil}])
    assert "\x1b" not in dot
    for line in dot.splitlines():
        assert line.replace('\\\\', '').replace('\\"', '').count('"') % 2 == 0, line
    assert "\nevil" not in dot and "\n  evil" not in dot
    assert dot_escape('a"b\\c') == 'a\\"b\\\\c'


def test_loaders_validate_input():
    with tempfile.TemporaryDirectory() as d:
        def write(name, data):
            path = os.path.join(d, name)
            with open(path, "w") as fh:
                fh.write(data if isinstance(data, str) else json.dumps(data))
            return path

        ok = write("d.json", [{"ip": "10.0.0.1", "hostname": "r"}, {"ip": "not-an-ip"}, "junk"])
        assert load_hosts(ok) == [{"ip": "10.0.0.1", "hostname": "r"}]
        for bad in (write("b1.json", {"ip": "1.1.1.1"}), write("b2.json", []), write("b3.json", "{oops")):
            with pytest.raises(ValueError):
                load_hosts(bad)
        with pytest.raises(ValueError):
            load_hosts(os.path.join(d, "missing.json"))

        scan = write("s.json", {"host": "x", "ip": "10.0.0.1", "ports": [{"port": 22, "open": True, "service": "ssh"}, {"port": 23, "open": False}]})
        assert load_scans([scan]) == {"10.0.0.1": [{"port": 22, "open": True, "service": "ssh"}]}
        with pytest.raises(ValueError):
            load_scans([write("s2.json", [1, 2])])


def test_example_files_in_the_readme_still_work():
    here = os.path.dirname(os.path.abspath(__file__))
    ex = lambda name: os.path.join(here, "..", "examples", name)
    hosts = load_hosts(ex("discover.example.json"))
    scans = load_scans([ex("scan.homeserver.json"), ex("scan.nas.json")])
    assert len(hosts) == 7 and set(scans) == {"192.168.1.10", "192.168.1.12"}
    dot = build_dot(hosts, scans)
    assert "open: 22/ssh, 53/dns, 8080/http-alt" in dot and "open: 22/ssh, 445/smb" in dot
    assert '"192.168.1.1" [label="192.168.1.1\\nrouter.lan\\nGateway"' in dot


def test_license_and_ci_files_exist_and_say_what_the_readme_claims():
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    text = open(os.path.join(root, "LICENSE"), encoding="utf-8").read()
    assert text.startswith("MIT License") and "Permission is hereby granted" in text
    workflow = open(os.path.join(root, ".github", "workflows", "ci.yml"), encoding="utf-8").read()
    assert "pytest" in workflow and '"3.9"' in workflow and '"3.13"' in workflow
    assert "requires-python" in open(os.path.join(root, "pyproject.toml"), encoding="utf-8").read()


def test_cli_topology(capsys):
    with tempfile.TemporaryDirectory() as d:
        disc = os.path.join(d, "d.json")
        with open(disc, "w") as fh:
            json.dump(HOSTS, fh)
        out = os.path.join(d, "net.dot")
        assert main(["topology", "--discover", disc, "-o", out, "--title", "Home"]) == 0
        text = open(out).read()
        assert 'label="Home"' in text and "192.168.1.20" in text

        assert main(["topology", "--discover", disc, "-o", "-"]) == 0
        assert capsys.readouterr().out.startswith("graph network")

        rc = main(["topology", "--discover", disc, "-o", out, "--png", os.path.join(d, "net.png")])
        if shutil.which("dot"):
            assert rc == 0 and os.path.getsize(os.path.join(d, "net.png")) > 100
        else:
            assert rc == 2 and "Graphviz" in capsys.readouterr().err

        assert main(["topology", "--discover", os.path.join(d, "none.json")]) == 2
