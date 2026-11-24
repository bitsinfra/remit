import json
import math
from pathlib import Path

import remit
from remit import core

VEC = Path(__file__).resolve().parents[3] / "spec" / "conformance"


def load(n):
    return json.loads((VEC / n).read_text())


def test_jcs_vectors():
    for c in load("jcs.json"):
        assert remit.canonicalize(c["input"]) == c["canonical"], c["input"]


def test_capacity_vectors():
    v = load("capacity.json")
    for c in v["valid"]:
        bits = remit.capacity(c["returns"], c["params"])
        assert abs(bits - c["bits"]) < 1e-6, (c["name"], bits)
        assert remit.capacity_ceil(bits) == c["bits_ceil"]
    for c in v["invalid"]:
        try:
            remit.capacity(c["returns"], {})
        except remit.RemitTypeError as e:
            assert e.code == c["code"], (c["name"], e.code)
        else:
            raise AssertionError(c["name"])


def test_remit_id_vectors():
    for c in load("remit_id.json"):
        assert remit.remit_id(c["manifest"]) == c["remit_id"]
        assert remit.params_sha256(c["manifest"]) == c["params_sha256"]


def test_ed25519_rfc8032_vector():
    # RFC 8032 §7.1 test 1
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    i = remit.Identity(seed)
    assert i.public_key == pk
    assert i.sign(b"") == sig
    env = remit.sign_envelope(core.MANIFEST_TYPE, b"{}", i)
    assert remit.open_envelope(env, core.MANIFEST_TYPE, pk) == b"{}"
    assert remit.public_key_from_did_key(i.did_key) == pk


def test_identity_file_interop():
    root = Path(__file__).resolve().parents[3]
    i = remit.Identity.load(str(root / "examples/personal-vault/keys/travel-agent.json"))
    assert i.did_key == json.loads((root / "examples/personal-vault/keys/travel-agent.json").read_text())["public_key"]
    assert i.key_id.startswith("did:web:travel-agent.example#z6Mk")


def test_free_slots_example():
    rt = remit.t.list(remit.t.struct(start=remit.t.timestamp("15m"), end=remit.t.timestamp("15m")), max=3)
    bits = remit.capacity(rt, {"from": "2026-11-24T00:00:00Z", "until": "2026-12-08T00:00:00Z"})
    assert abs(bits - 64.35) < 0.1
    assert remit.capacity_ceil(bits) + remit.STATUS_BITS == 68


def test_native_parity():
    """Rust core (PyO3) and pure Python agree, when the native module is installed."""
    if remit.native is None:
        return
    for c in load("capacity.json")["valid"]:
        r = json.loads(remit.native.capacity(json.dumps(c["returns"]), json.dumps(c["params"])))
        assert abs(r["bits"] - remit.capacity(c["returns"], c["params"])) < 1e-9, c["name"]
    for c in load("jcs.json"):
        assert remit.native.canonicalize(json.dumps(c["input"])) == remit.canonicalize(c["input"])
    for c in load("remit_id.json"):
        assert json.loads(remit.native.remit_id(json.dumps(c["manifest"])))["remit_id"] == remit.remit_id(c["manifest"])
    assert json.loads(remit.native.check_sql("SELECT now()"))["ok"] is False



def test_date_capacity_is_independent_of_timezone():
    import os
    import time
    previous = os.environ.get("TZ")
    try:
        for zone in ("UTC", "America/New_York"):
            os.environ["TZ"] = zone
            if hasattr(time, "tzset"):
                time.tzset()
            assert core.capacity({"date": {"min": "2026-03-08", "max": "2026-03-09"}}) == 1
    finally:
        if previous is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = previous
        if hasattr(time, "tzset"):
            time.tzset()


def test_pure_result_validation():
    from remit.validation import validate
    rt = {"struct": {"n": {"int": {"min": 0, "max": 3}}, "s": {"string": {"max_len": 2, "charset": "digits"}}}}
    validate(rt, {}, {"n": 2, "s": "12"})
    for value in ({"n": 4, "s": "12"}, {"n": True, "s": "12"}, {"n": 2, "s": "ab"}, {"n": 2, "s": "12", "extra": 1}):
        try:
            validate(rt, {}, value)
        except ValueError:
            pass
        else:
            raise AssertionError(value)


if __name__ == "__main__":
    for name, f in list(globals().items()):
        if name.startswith("test_"):
            f()
            print("ok", name)
