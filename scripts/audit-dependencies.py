import json
import subprocess
import sys


metadata = json.loads(subprocess.check_output([
    "cargo", "metadata", "--format-version", "1", "--all-features", "--locked",
]))
packages = {p["id"]: p for p in metadata["packages"]}
affected = [
    node for node in metadata["resolve"]["nodes"]
    if packages[node["id"]]["name"] == "nalgebra"
    and (0, 11, 0) <= tuple(map(int, packages[node["id"]]["version"].split("."))) < (0, 27, 1)
]
args = ["cargo", "audit"]
if affected and all(not any("serde" in f for f in node["features"]) for node in affected):
    print("nalgebra: affected serde deserialization is disabled in the full feature graph", flush=True)
    args += ["--ignore", "RUSTSEC-2021-0070"]
sys.exit(subprocess.call(args))
