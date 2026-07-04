from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path

SOURCE = Path("source")
SOURCE_IP = SOURCE / "ip"
OUT = Path("output")
YAML_OUT = OUT / "yaml"
DOMAINS_OUT = OUT / "domains"
IP_OUT = OUT / "ip"
GEOSITE_DATA = OUT / "geosite-data"
GEOIP_DATA = OUT / "geoip-data"
GEOIP_CONFIG = OUT / "geoip-config.json"
IMPORT_GEOSITE_DIR = OUT / "import/geosite-unpacked"
IMPORT_GEOIP_DIR = OUT / "import/geoip-unpacked"
REPO_URL = "https://github.com/R0iZ/ownrouterules"

DOMAIN_RULE_ORDER = {
    "DOMAIN-SUFFIX": 0,
    "DOMAIN": 1,
    "DOMAIN-KEYWORD": 2,
    "DOMAIN-REGEX": 3,
}

IP_RULE_ORDER = {
    "IP-CIDR": 0,
    "IP-CIDR6": 1,
}

CLASSICAL_PREFIXES = (
    "DOMAIN-SUFFIX,",
    "DOMAIN-KEYWORD,",
    "DOMAIN,",
    "DOMAIN-REGEX,",
    "IP-CIDR,",
    "IP-CIDR6,",
)

IP_PREFIXES = (
    "IP-CIDR,",
    "IP-CIDR6,",
)

for p in [YAML_OUT, DOMAINS_OUT, IP_OUT, GEOSITE_DATA, GEOIP_DATA]:
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


def parse_v2dat_geosite_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("keyword:"):
        return "DOMAIN-KEYWORD", line[8:].strip()
    if line.startswith("regexp:"):
        return "DOMAIN-REGEX", line[7:].strip()
    if line.startswith("full:"):
        return "DOMAIN", line[5:].strip()
    return "DOMAIN-SUFFIX", line


def cidr_to_rule(cidr: str) -> tuple[str, str]:
    return ("IP-CIDR6", cidr) if ":" in cidr else ("IP-CIDR", cidr)


def normalize_domain(domain: str) -> str | None:
    domain = domain.strip().strip(".").strip()
    if not domain:
        return None
    return domain


def geosite_domain(rule_type: str, value: str) -> str | None:
    if rule_type == "DOMAIN-SUFFIX":
        return normalize_domain(value)
    if rule_type == "DOMAIN":
        return normalize_domain(value)
    return None


def sort_rules(rules: list[tuple[str, str]], order: dict[str, int]) -> list[tuple[str, str]]:
    return sorted(dict.fromkeys(rules), key=lambda item: (order.get(item[0], 99), item[1]))


def build_yaml(name: str, rules: list[tuple[str, str]], order: dict[str, int]) -> str:
    counts = Counter(rule_type for rule_type, _ in rules)
    display_name = name.replace("-", " ").replace("_", " ").title()
    updated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    header = [
        f"# NAME: {display_name}",
        "# AUTHOR: R0iZ",
        f"# REPO: {REPO_URL}",
        f"# UPDATED: {updated}",
    ]
    for key in order:
        if counts[key]:
            header.append(f"# {key}: {counts[key]}")
    header.append(f"# TOTAL: {len(rules)}")
    header.append("payload:")

    body = [f"  - {rule_type},{value}" for rule_type, value in rules]
    return "\n".join(header + body) + "\n"


def load_v2dat_geosite_rules(directory: Path) -> list[tuple[str, str]]:
    if not directory.is_dir():
        return []

    rules: list[tuple[str, str]] = []
    for path in directory.rglob("*.txt"):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if rule := parse_v2dat_geosite_line(line):
                rules.append(rule)
    return rules


def load_v2dat_geoip_rules(directory: Path) -> list[tuple[str, str]]:
    if not directory.is_dir():
        return []

    rules: list[tuple[str, str]] = []
    for path in directory.rglob("*.txt"):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            cidr = parse_ip(line)
            if cidr:
                rules.append(cidr_to_rule(cidr))
    return rules


def rules_to_domain_suffixes(rules: list[tuple[str, str]]) -> list[str]:
    suffixes: set[str] = set()
    for rule_type, value in rules:
        if rule_type in {"DOMAIN-SUFFIX", "DOMAIN"}:
            if domain := normalize_domain(value):
                suffixes.add(domain)
    return sorted(suffixes)


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


all_domain_rules: list[tuple[str, str]] = []
all_ip_rules: list[tuple[str, str]] = []

for src in SOURCE.glob("*.txt"):
    name = src.stem
    parsed = [rule for line in src.read_text(encoding="utf-8").splitlines() if (rule := parse_rule(line))]
    rules = sort_rules(parsed, DOMAIN_RULE_ORDER)

    if not rules:
        print(f"skip {name}: no rules")
        continue

    domain_rules = [rule for rule in rules if rule[0] in DOMAIN_RULE_ORDER]
    all_domain_rules.extend(domain_rules)

    (YAML_OUT / f"{name}.yaml").write_text(build_yaml(name, domain_rules, DOMAIN_RULE_ORDER), encoding="utf-8")

    geosite_domains = sorted(
        {
            domain
            for rule_type, value in domain_rules
            if (domain := geosite_domain(rule_type, value))
        }
    )
    (GEOSITE_DATA / name).write_text("\n".join(geosite_domains) + "\n", encoding="utf-8")

    print(f"prepared {name} ({len(domain_rules)} domain rules, {len(geosite_domains)} geosite domains)")

for src in SOURCE_IP.glob("*.txt"):
    name = src.stem
    cidrs = sorted({cidr for line in src.read_text(encoding="utf-8").splitlines() if (cidr := parse_ip(line))})

    if not cidrs:
        print(f"skip ip/{name}: no cidrs")
        continue

    ip_rules = [cidr_to_rule(cidr) for cidr in cidrs]
    all_ip_rules.extend(ip_rules)

    ip_text = "\n".join(cidrs) + "\n"
    (IP_OUT / f"{name}.txt").write_text(ip_text, encoding="utf-8")
    (GEOIP_DATA / name).write_text(ip_text, encoding="utf-8")

    print(f"prepared ip/{name} ({len(cidrs)} cidrs)")

imported_domain_rules = load_v2dat_geosite_rules(IMPORT_GEOSITE_DIR)
imported_ip_rules = load_v2dat_geoip_rules(IMPORT_GEOIP_DIR)
all_domain_rules.extend(imported_domain_rules)
all_ip_rules.extend(imported_ip_rules)

if imported_domain_rules:
    print(f"imported {len(imported_domain_rules)} domain rules from runetfreedom geosite.dat")
if imported_ip_rules:
    print(f"imported {len(imported_ip_rules)} ip rules from runetfreedom geoip.dat")

merged_domains = sort_rules(all_domain_rules, DOMAIN_RULE_ORDER)
merged_ips = sort_rules(all_ip_rules, IP_RULE_ORDER)

if merged_domains:
    # Plain suffix list for Mihomo behavior: domain (much lighter than classical YAML).
    suffixes = rules_to_domain_suffixes(merged_domains)
    (DOMAINS_OUT / "blocked-domains.txt").write_text("\n".join(suffixes) + "\n", encoding="utf-8")
    print(f"wrote domains/blocked-domains.txt ({len(suffixes)} suffixes)")

    keyword_regex = [rule for rule in merged_domains if rule[0] in {"DOMAIN-KEYWORD", "DOMAIN-REGEX"}]
    if keyword_regex:
        (YAML_OUT / "blocked-domains-extra.yaml").write_text(
            build_yaml("Blocked Domains Extra", keyword_regex, DOMAIN_RULE_ORDER),
            encoding="utf-8",
        )
        print(f"wrote blocked-domains-extra.yaml ({len(keyword_regex)} keyword/regex rules)")

if merged_ips:
    # Plain text for Mihomo behavior: ipcidr (classical YAML is too slow on routers).
    cidrs = [value for _, value in merged_ips]
    (IP_OUT / "blocked-ip.txt").write_text("\n".join(cidrs) + "\n", encoding="utf-8")
    print(f"wrote ip/blocked-ip.txt ({len(cidrs)} cidrs)")

if write_geoip_config():
    print(f"wrote {GEOIP_CONFIG}")
else:
    print("no local IP lists, skip geoip.dat config")
