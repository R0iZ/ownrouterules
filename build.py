from pathlib import Path
import json
import subprocess
import shutil

SOURCE = Path("source")
OUT = Path("output")
YAML_OUT = OUT / "yaml"
SRS_JSON_OUT = OUT / "srs-json"
SRS_OUT = OUT / "srs"
GEOSITE_DATA = OUT / "geosite-data"

for p in [YAML_OUT, SRS_JSON_OUT, SRS_OUT, GEOSITE_DATA]:
    p.mkdir(parents=True, exist_ok=True)


def clean(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    line = line.removeprefix("+.")
    line = line.removeprefix(".")
    line = line.removeprefix("domain:")
    line = line.removeprefix("full:")
    return line.strip()


for src in SOURCE.glob("*.txt"):
    name = src.stem
    domains = sorted(
        {
            d
            for line in src.read_text(encoding="utf-8").splitlines()
            if (d := clean(line))
        }
    )

    if not domains:
        print(f"skip {name}: no domains")
        continue

    yaml_text = "payload:\n" + "\n".join(f"  - '+.{d}'" for d in domains) + "\n"
    (YAML_OUT / f"{name}.yaml").write_text(yaml_text, encoding="utf-8")

    srs_json = {
        "version": 3,
        "rules": [{"domain_suffix": domains}],
    }
    json_path = SRS_JSON_OUT / f"{name}.json"
    json_path.write_text(json.dumps(srs_json, ensure_ascii=False, indent=2), encoding="utf-8")

    geosite_text = "\n".join(f"domain:{d}" for d in domains) + "\n"
    (GEOSITE_DATA / name).write_text(geosite_text, encoding="utf-8")

    print(f"prepared {name} ({len(domains)} domains)")

if shutil.which("sing-box"):
    for json_file in SRS_JSON_OUT.glob("*.json"):
        out_file = SRS_OUT / f"{json_file.stem}.srs"
        subprocess.run(
            ["sing-box", "rule-set", "compile", "--output", str(out_file), str(json_file)],
            check=True,
        )
        print(f"compiled {out_file.name}")
else:
    print("sing-box not found, skip .srs build")
