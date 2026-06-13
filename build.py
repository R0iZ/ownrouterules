from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

SOURCE = Path("source")
OUT = Path("output")
YAML_OUT = OUT / "yaml"
GEOSITE_DATA = OUT / "geosite-data"
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

for p in [YAML_OUT, GEOSITE_DATA]:
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
