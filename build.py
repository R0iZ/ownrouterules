from pathlib import Path

SOURCE = Path("source")
OUT = Path("output")
YAML_OUT = OUT / "yaml"
GEOSITE_DATA = OUT / "geosite-data"

for p in [YAML_OUT, GEOSITE_DATA]:
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

    geosite_text = "\n".join(domains) + "\n"
    (GEOSITE_DATA / name).write_text(geosite_text, encoding="utf-8")

    print(f"prepared {name} ({len(domains)} domains)")
