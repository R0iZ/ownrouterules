from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path

SOURCE = Path("source")
SOURCE_IP = SOURCE / "ip"
OUT = Path("output")
YAML_OUT = OUT / "yaml"
IP_OUT = OUT / "ip"
GEOSITE_DATA = OUT / "geosite-data"
GEOIP_DATA = OUT / "geoip-data"
GEOIP_CONFIG = OUT / "geoip-config.json"
REPO_URL = "https://github.com/R0iZ/ownrouterules"

RULE_ORDER = {
    "DOMAIN-SUFFIX": 0,
    "DOMAIN": 1,
    "DOMAIN-KEYWORD": 2,
    "IP-CIDR": 3,
    "IP-CIDR6": 4,
}

CLASSICAL_PREFIXES = (
    "DOMAIN-SUFFIX,",
    "DOMAIN-KEYWORD,",
    "DOMAIN,",
    "IP-CIDR,",
    "IP-CIDR6,",
)

IP_PREFIXES = (
    "IP-CIDR,",
    "IP-CIDR6,",
)

for p in [YAML_OUT, IP_OUT, GEOSITE_DATA, GEOIP_DATA]:
    p.mkdir(parents=True, exist_ok=True)


def parse_rule(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    upper = line.upper()
    for prefix in CLASSICAL_PREFIXES:
        if upper.startswith(prefix):
            rule_type = prefix[:-1]
            value = line[len(prefix) :].strip()
            return rule_type, value

    if upper.startswith("FULL:"):
        return "DOMAIN", line[5:].strip()

    value = line.removeprefix("+.").removeprefix(".").removeprefix("domain:").strip()
    if not value:
        return None
    return "DOMAIN-SUFFIX", value


def parse_ip(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    upper = line.upper()
    for prefix in IP_PREFIXES:
        if upper.startswith(prefix):
            return line[len(prefix) :].strip()

    return line


def geosite_domain(rule_type: str, value: str) -> str | None:
    if rule_type == "DOMAIN-SUFFIX":
        return value.lstrip(".")
    if rule_type == "DOMAIN":
        return value
    return None


def build_yaml(name: str, rules: list[tuple[str, str]]) -> str:
    counts = Counter(rule_type for rule_type, _ in rules)
    display_name = name.replace("-", " ").replace("_", " ").title()
    updated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    header = [
        f"# NAME: {display_name}",
        "# AUTHOR: R0iZ",
        f"# REPO: {REPO_URL}",
        f"# UPDATED: {updated}",
    ]
    for key in RULE_ORDER:
        if counts[key]:
            header.append(f"# {key}: {counts[key]}")
    header.append(f"# TOTAL: {len(rules)}")
    header.append("payload:")

    body = [f"  - {rule_type},{value}" for rule_type, value in rules]
    return "\n".join(header + body) + "\n"


def write_geoip_config() -> bool:
    if not any(GEOIP_DATA.iterdir()):
        return False

    config = {
        "input": [
            {
                "type": "text",
                "action": "add",
                "args": {
                    "inputDir": str(GEOIP_DATA.resolve()),
                    "removePrefixesInLine": ["IP-CIDR,", "IP-CIDR6,"],
                },
            }
        ],
        "output": [
            {
                "type": "v2rayGeoIPDat",
                "action": "output",
                "args": {
                    "outputDir": str(OUT.resolve()),
                    "outputName": "geoip.dat",
                },
            }
        ],
    }
    GEOIP_CONFIG.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return True


for src in SOURCE.glob("*.txt"):
    name = src.stem
    parsed = [rule for line in src.read_text(encoding="utf-8").splitlines() if (rule := parse_rule(line))]

    rules = sorted(
        dict.fromkeys(parsed),
        key=lambda item: (RULE_ORDER.get(item[0], 99), item[1]),
    )

    if not rules:
        print(f"skip {name}: no rules")
        continue

    (YAML_OUT / f"{name}.yaml").write_text(build_yaml(name, rules), encoding="utf-8")

    geosite_domains = sorted(
        {
            domain
            for rule_type, value in rules
            if (domain := geosite_domain(rule_type, value))
        }
    )
    (GEOSITE_DATA / name).write_text("\n".join(geosite_domains) + "\n", encoding="utf-8")

    print(f"prepared {name} ({len(rules)} rules, {len(geosite_domains)} geosite domains)")

for src in SOURCE_IP.glob("*.txt"):
    name = src.stem
    cidrs = sorted({cidr for line in src.read_text(encoding="utf-8").splitlines() if (cidr := parse_ip(line))})

    if not cidrs:
        print(f"skip ip/{name}: no cidrs")
        continue

    ip_text = "\n".join(cidrs) + "\n"
    (IP_OUT / f"{name}.txt").write_text(ip_text, encoding="utf-8")
    (GEOIP_DATA / name).write_text(ip_text, encoding="utf-8")

    print(f"prepared ip/{name} ({len(cidrs)} cidrs)")

if write_geoip_config():
    print(f"wrote {GEOIP_CONFIG}")
else:
    print("no IP lists, skip geoip.dat config")
