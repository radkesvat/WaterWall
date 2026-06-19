#!/usr/bin/env python3
"""Generate Router geosite JSON data from the local domain-list-community/data tree."""

from __future__ import annotations

import dataclasses
import enum
import json
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple


SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "domain-list-community" / "data"
OUTPUT_JSON = SCRIPT_DIR / "geosite_generated.json"


class RuleType(enum.IntEnum):
    PLAIN = 0
    REGEX = 1
    ROOT_DOMAIN = 2
    FULL = 3

    @property
    def json_name(self) -> str:
        return {
            RuleType.PLAIN: "plain",
            RuleType.REGEX: "regex",
            RuleType.ROOT_DOMAIN: "domain",
            RuleType.FULL: "full",
        }[self]


@dataclasses.dataclass(frozen=True, order=True)
class Attr:
    key: str
    bool_value: bool = True


@dataclasses.dataclass(frozen=True)
class Rule:
    type: RuleType
    value: str
    attrs: Tuple[Attr, ...] = ()

    def dedup_key(self) -> Tuple[int, str, Tuple[Tuple[str, bool], ...]]:
        return (
            int(self.type),
            self.value,
            tuple((attr.key, attr.bool_value) for attr in sorted(self.attrs)),
        )


@dataclasses.dataclass(frozen=True)
class Include:
    target: str
    require_attrs: Tuple[str, ...] = ()
    exclude_attrs: Tuple[str, ...] = ()


@dataclasses.dataclass
class RawList:
    name: str
    rules: List[Rule] = dataclasses.field(default_factory=list)
    includes: List[Include] = dataclasses.field(default_factory=list)


LINE_RE = re.compile(r"^([^\s]+)(?:\s+(.*))?$")


def strip_comment(line: str) -> str:
    return line.split("#", 1)[0].strip()


def normalize_list_name(name: str) -> str:
    return name.strip().lower()


def normalize_value(rule_type: RuleType, value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("empty rule value")
    if rule_type == RuleType.REGEX:
        return value

    normalized = value.rstrip(".").lower()
    if not normalized:
        raise ValueError("empty rule value")
    return normalized


def parse_attrs_and_affiliations(rest: str) -> Tuple[Tuple[Attr, ...], Tuple[str, ...]]:
    attrs: List[Attr] = []
    affiliations: List[str] = []

    if not rest:
        return (), ()

    for token in rest.split():
        if token.startswith("@") and len(token) > 1:
            attrs.append(Attr(token[1:], True))
        elif token.startswith("&") and len(token) > 1:
            affiliations.append(normalize_list_name(token[1:]))
        else:
            raise ValueError(f"unknown token after rule: {token!r}")

    return tuple(sorted(set(attrs))), tuple(sorted(set(affiliations)))


def parse_include(first_token: str, rest: str) -> Include:
    target = normalize_list_name(first_token[len("include:"):])
    if not target:
        raise ValueError("empty include target")

    require: List[str] = []
    exclude: List[str] = []

    if rest:
        for token in rest.split():
            if token.startswith("@-") and len(token) > 2:
                exclude.append(token[2:])
            elif token.startswith("@") and len(token) > 1:
                require.append(token[1:])
            else:
                raise ValueError(f"unknown token after include: {token!r}")

    return Include(
        target=target,
        require_attrs=tuple(sorted(set(require))),
        exclude_attrs=tuple(sorted(set(exclude))),
    )


def parse_rule(first_token: str, rest: str) -> Tuple[Rule, Tuple[str, ...]]:
    if first_token.startswith("domain:"):
        rule_type = RuleType.ROOT_DOMAIN
        value = first_token[len("domain:"):]
    elif first_token.startswith("full:"):
        rule_type = RuleType.FULL
        value = first_token[len("full:"):]
    elif first_token.startswith("keyword:"):
        rule_type = RuleType.PLAIN
        value = first_token[len("keyword:"):]
    elif first_token.startswith("regexp:"):
        rule_type = RuleType.REGEX
        value = first_token[len("regexp:"):]
    else:
        rule_type = RuleType.ROOT_DOMAIN
        value = first_token

    attrs, affiliations = parse_attrs_and_affiliations(rest or "")
    return Rule(type=rule_type, value=normalize_value(rule_type, value), attrs=attrs), affiliations


def parse_data_file(path: Path, name: str) -> Tuple[RawList, List[Tuple[str, Rule]]]:
    raw = RawList(name=name)
    affiliated_rules: List[Tuple[str, Rule]] = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, original in enumerate(file, 1):
            line = strip_comment(original)
            if not line:
                continue

            match = LINE_RE.match(line)
            if not match:
                raise ValueError(f"{path}:{line_number}: cannot parse line: {original.rstrip()!r}")

            first_token = match.group(1)
            rest = match.group(2) or ""

            try:
                if first_token.startswith("include:"):
                    raw.includes.append(parse_include(first_token, rest))
                else:
                    rule, affiliations = parse_rule(first_token, rest)
                    raw.rules.append(rule)
                    for affiliation in affiliations:
                        affiliated_rules.append((affiliation, rule))
            except ValueError as exc:
                raise ValueError(f"{path}:{line_number}: {exc}; line={original.rstrip()!r}") from exc

    return raw, affiliated_rules


def read_raw_lists(data_dir: Path) -> Dict[str, RawList]:
    if not data_dir.is_dir():
        raise FileNotFoundError(f"data directory does not exist: {data_dir}")

    lists: Dict[str, RawList] = {}
    pending_affiliations: List[Tuple[str, Rule]] = []

    for path in sorted(data_dir.iterdir()):
        if not path.is_file():
            continue
        if path.name.startswith(".") or path.name.endswith("~"):
            continue

        name = normalize_list_name(path.name)
        raw, affiliations = parse_data_file(path, name)
        lists[name] = raw
        pending_affiliations.extend(affiliations)

    for target, rule in pending_affiliations:
        lists.setdefault(target, RawList(name=target)).rules.append(rule)

    return lists


def rule_matches_include_filter(rule: Rule, include: Include) -> bool:
    attr_keys = {attr.key for attr in rule.attrs if attr.bool_value}
    return all(key in attr_keys for key in include.require_attrs) and all(
        key not in attr_keys for key in include.exclude_attrs
    )


def resolve_lists(raw_lists: Dict[str, RawList]) -> Dict[str, List[Rule]]:
    resolved: Dict[str, List[Rule]] = {}
    resolving: Set[str] = set()

    def resolve_one(name: str) -> List[Rule]:
        normalized_name = normalize_list_name(name)
        if normalized_name in resolved:
            return resolved[normalized_name]
        if normalized_name in resolving:
            cycle = " -> ".join(sorted(resolving) + [normalized_name])
            raise ValueError(f"include cycle detected: {cycle}")
        if normalized_name not in raw_lists:
            raise KeyError(f"include references missing list: {normalized_name}")

        resolving.add(normalized_name)
        raw = raw_lists[normalized_name]
        result: List[Rule] = list(raw.rules)

        for include in raw.includes:
            included_rules = resolve_one(include.target)
            result.extend(rule for rule in included_rules if rule_matches_include_filter(rule, include))

        resolving.remove(normalized_name)

        by_key: Dict[Tuple[int, str, Tuple[Tuple[str, bool], ...]], Rule] = {}
        for rule in result:
            by_key.setdefault(rule.dedup_key(), rule)

        resolved[normalized_name] = [by_key[key] for key in sorted(by_key)]
        return resolved[normalized_name]

    for name in sorted(raw_lists):
        resolve_one(name)

    return resolved


def rule_to_json(rule: Rule) -> Dict[str, object]:
    return {
        "type": rule.type.json_name,
        "value": rule.value,
        "attributes": [
            {
                "key": attr.key,
                "type": "bool",
                "value": attr.bool_value,
            }
            for attr in sorted(rule.attrs)
        ],
    }


def list_to_json(list_name: str, rules: List[Rule]) -> Dict[str, object]:
    return {
        "name": list_name,
        "code": None,
        "file_path": None,
        "resource_hash": None,
        "domains": [rule_to_json(rule) for rule in rules],
    }


def generate_json_data(resolved: Dict[str, List[Rule]]) -> Dict[str, object]:
    return {
        "format": "waterwall-router-geosite-v1",
        "lists": [list_to_json(list_name, resolved[list_name]) for list_name in sorted(resolved)],
    }


def main() -> None:
    raw_lists = read_raw_lists(DATA_DIR)
    resolved = resolve_lists(raw_lists)
    output = generate_json_data(resolved)

    OUTPUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_JSON.open("w", encoding="utf-8") as file:
        json.dump(output, file, ensure_ascii=False, separators=(",", ":"))
        file.write("\n")

    rule_count = sum(len(rules) for rules in resolved.values())
    print(f"Wrote {OUTPUT_JSON}: {len(resolved)} lists, {rule_count} rules")


if __name__ == "__main__":
    main()
