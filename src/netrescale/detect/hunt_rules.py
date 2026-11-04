"""Private manual-hunt rules and bounded, isolated rule evaluation."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from netrescale.collect.device_logs import LogSource
from netrescale.detect.findings import finding_document, from_rule_hit, from_session_reuse
from netrescale.detect.rules import (
    ListMatcher,
    RuleEngine,
    RuleError,
    load_rule_documents,
    parse_rule,
)
from netrescale.detect.sessions import SessionTracker
from netrescale.parse.nslog import parse_line
from netrescale.secrets.vault import atomic_write

MAX_INPUT = 8 * 1024 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
MAX_RULES = 100
RULE_TIMEOUT = 30
ShortText = Annotated[str, Field(min_length=1, max_length=128)]
PatternText = Annotated[str, Field(min_length=1, max_length=2048)]


class RuleRevisionConflict(RuleError):
    pass


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class MatchSpec(StrictModel):
    raw_regex: PatternText | None = None
    message_regex: PatternText | None = None
    fields: dict[ShortText, PatternText] = Field(default_factory=dict, max_length=16)
    fields_differ: list[ShortText] | None = Field(default=None, min_length=2, max_length=2)
    not_in_list: dict[ShortText, Literal["admin_networks", "admin_users"]] = Field(
        default_factory=dict, max_length=16)

    @model_validator(mode="after")
    def nonempty(self) -> MatchSpec:
        if not any((self.raw_regex, self.message_regex, self.fields,
                    self.fields_differ, self.not_in_list)):
            raise ValueError("at least one match condition is required")
        return self


class Vector(StrictModel):
    source: LogSource
    line: str = Field(min_length=1, max_length=8192)


class Vectors(StrictModel):
    positive: list[Vector] = Field(min_length=1, max_length=20)
    negative: list[Vector] = Field(min_length=1, max_length=20)


class ThresholdSpec(StrictModel):
    count: int = Field(ge=1, le=1000)
    window_seconds: int = Field(ge=1, le=86400)
    group_by: list[ShortText] = Field(default_factory=list, max_length=10)


class RuleSpec(StrictModel):
    id: str = Field(pattern=r"^custom-[a-z0-9][a-z0-9._-]{0,55}$")
    title: str = Field(min_length=1, max_length=200)
    severity: Literal["info", "low", "medium", "high", "critical"]
    enabled: bool = True
    sources: list[LogSource] = Field(min_length=1, max_length=8)
    event_types: list[ShortText] = Field(default_factory=list, max_length=20)
    events: list[ShortText] = Field(default_factory=list, max_length=20)
    match: MatchSpec
    threshold: ThresholdSpec | None = None
    dedup_by: list[ShortText] | None = Field(default=None, max_length=10)
    cve: list[Annotated[str, Field(pattern=r"^CVE-\d{4}-\d{4,}$")]] = Field(
        default_factory=list, max_length=20)
    mitre: list[ShortText] = Field(default_factory=list, max_length=20)
    references: list[Annotated[str, Field(max_length=500)]] = Field(
        default_factory=list, max_length=20)
    description: str = Field(default="", max_length=2000)
    provenance: str = Field(default="Custom rule", max_length=500)
    tests: Vectors


def templates() -> dict[str, Any]:
    document = yaml.safe_load(resources.files("netrescale.data")
                              .joinpath("hunt_templates.yaml").read_text("utf-8"))
    source = document["source"]
    return {"source": source, "items": [
        {**rule, "provenance": source["provenance"],
         "references": [f"User-supplied {source['name']} v{source['version']}"]}
        for rule in document["rules"]
    ]}


def validate_documents(text: str, values: dict[str, list[str]]) -> dict[str, Any]:
    if len(text.encode()) > 256 * 1024:
        raise RuleError("Rule input exceeds 256 KiB")
    loaded = yaml.safe_load(text)
    documents = loaded if isinstance(loaded, list) else [loaded]
    if not 1 <= len(documents) <= MAX_RULES:
        raise RuleError("Provide between 1 and 100 rules")
    normalized = [RuleSpec.model_validate(document).model_dump(exclude_none=True)
                  for document in documents]
    if len({document["id"] for document in normalized}) != len(normalized):
        raise RuleError("Duplicate custom rule IDs")
    if len(json.dumps(normalized)) > 512 * 1024:
        raise RuleError("Expanded rules exceed their size limit")
    lists = {name: ListMatcher(entries) for name, entries in values.items() if entries}
    tested = 0
    for document in normalized:
        rule = parse_rule(document)
        for expected, vectors in ((True, rule.tests_positive), (False, rule.tests_negative)):
            for source, line in vectors:
                engine = RuleEngine([rule], lists)
                if engine.disabled:
                    raise RuleError(f"{rule.id}: {engine.disabled[rule.id]}")
                event = parse_line(source, line, "rule-test")
                count = rule.threshold.count if rule.threshold else 1
                matched = any(bool(engine.evaluate(event)) for _number in range(count))
                if matched != expected:
                    kind = "positive" if expected else "negative"
                    raise RuleError(f"{rule.id}: {kind} test {tested + 1} failed")
                tested += 1
    return {"documents": normalized, "tested": tested}


class HuntRuleStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self) -> tuple[str, dict[str, Any]]:
        if not self.path.exists():
            return "", {"version": 1, "rules": {}}
        if self.path.stat().st_size > 2 * 1024 * 1024:
            raise RuleError("Custom rule store exceeds its size limit")
        raw = self.path.read_bytes()
        document = json.loads(raw)
        if (document.get("version") != 1 or not isinstance(document.get("rules"), dict)
                or len(document["rules"]) > MAX_RULES):
            raise RuleError("Invalid custom rule store")
        for identity, entry in document["rules"].items():
            rule = RuleSpec.model_validate(entry["document"])
            if identity != rule.id:
                raise RuleError("Custom rule ID mismatch")
        return hashlib.sha256(raw).hexdigest(), document

    def catalog(self) -> dict[str, Any]:
        revision, saved = self.read()
        items = [{"document": document, "origin": "bundled", "enabled": True}
                 for document in load_rule_documents()]
        items += [{**entry, "origin": "custom", "enabled": entry["document"]["enabled"]}
                  for entry in saved["rules"].values()]
        return {"revision": revision, "items": items}

    def active(self) -> list[dict[str, Any]]:
        return [item["document"] for item in self.catalog()["items"] if item["enabled"]]

    def save(self, documents: list[dict[str, Any]], expected: str, actor: str) -> str:
        revision, saved = self.read()
        if revision != expected:
            raise RuleRevisionConflict("Rules changed; refresh before saving")
        for document in documents:
            normalized = RuleSpec.model_validate(document).model_dump(exclude_none=True)
            saved["rules"][normalized["id"]] = {
                "document": normalized, "updated_by": actor,
                "updated_at": datetime.now(UTC).isoformat(),
            }
        if len(saved["rules"]) > MAX_RULES:
            raise RuleError("At most 100 custom hunt rules can be stored")
        raw = json.dumps(saved, indent=2).encode()
        if len(raw) > 2 * 1024 * 1024:
            raise RuleError("Custom rule store exceeds its size limit")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_write(self.path, raw, backup=True)
        return hashlib.sha256(raw).hexdigest()

    def delete(self, identity: str, expected: str) -> str:
        revision, saved = self.read()
        if revision != expected:
            raise RuleRevisionConflict("Rules changed; refresh before deleting")
        if identity not in saved["rules"]:
            raise RuleError("Only saved custom rules can be deleted")
        del saved["rules"][identity]
        raw = json.dumps(saved, indent=2).encode()
        atomic_write(self.path, raw, backup=True)
        return hashlib.sha256(raw).hexdigest()


def scan(packet: dict[str, Any]) -> dict[str, Any]:
    rules = [parse_rule(document) for document in packet["rules"]]
    lists = {name: ListMatcher(entries) for name, entries in packet.get("lists", {}).items()
             if entries}
    engine = RuleEngine(rules, lists)
    tracker = SessionTracker()
    lines = packet["text"].splitlines()
    if len(lines) > 10000:
        raise RuleError("Limit hunts to 10000 lines")
    findings = []
    scanned = 0
    for line in lines:
        event = parse_line(packet["source"], line, packet["device"],
                           packet.get("date_format", "YYYYMMDD"), packet.get("timezone", "UTC"))
        findings += [finding_document(from_rule_hit(hit)) for hit in engine.evaluate(event)]
        findings += [finding_document(from_session_reuse(hit)) for hit in tracker.observe(event)]
        scanned += 1
        if len(findings) >= 500:
            break
    return {"findings": findings[:500], "disabled_rules": engine.disabled,
            "lines": scanned, "input_lines": len(lines),
            "truncated": len(findings) > 500 or scanned < len(lines)}


async def run_worker(packet: dict[str, Any], *, timeout: float = RULE_TIMEOUT) -> dict[str, Any]:
    raw = json.dumps(packet).encode()
    if len(raw) > MAX_INPUT:
        raise RuleError("Hunt input and rules exceed the worker input limit")
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "netrescale.detect.hunt_rules", stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        env={"PYTHONPATH": os.environ.get("PYTHONPATH", ""), "PYTHONIOENCODING": "utf-8"},
    )
    try:
        async with asyncio.timeout(timeout):
            assert process.stdin is not None and process.stdout is not None
            process.stdin.write(raw)
            await process.stdin.drain()
            process.stdin.close()
            output = bytearray()
            while chunk := await process.stdout.read(65536):
                output.extend(chunk)
                if len(output) > MAX_OUTPUT:
                    raise RuleError("Hunt results exceed the output limit; narrow the input")
            await process.wait()
    except TimeoutError:
        raise RuleError("Rule evaluation exceeded its time limit; simplify the pattern") from None
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
    if process.returncode != 0:
        raise RuleError("Rule worker stopped before completing; simplify the rules or input")
    try:
        response = json.loads(output)
    except ValueError:
        raise RuleError("Rule worker returned an invalid response") from None
    if not response["ok"]:
        raise RuleError(response["error"])
    result: dict[str, Any] = response["result"]
    return result


def _main() -> None:
    try:
        import resource

        with contextlib.suppress(OSError, ValueError):
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    except ImportError:
        pass
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise RuleError("Worker input exceeds its limit")
        packet = json.loads(raw)
        result = (validate_documents(packet["text"], packet.get("lists", {}))
                  if packet["mode"] == "validate" else scan(packet))
        output = json.dumps({"ok": True, "result": result}).encode()
        if len(output) > MAX_OUTPUT:
            raise RuleError("Hunt results exceed the output limit; narrow the input")
    except ValidationError as exc:
        fields = [".".join(map(str, error["loc"]))
                  for error in exc.errors(include_input=False, include_context=False)]
        output = json.dumps({"ok": False,
                             "error": "Invalid rule fields: " + ", ".join(fields)}).encode()
    except (ValueError, TypeError, KeyError, RecursionError, MemoryError, yaml.YAMLError) as exc:
        output = json.dumps({"ok": False,
                             "error": str(exc)[:1000] or "Invalid rule input"}).encode()
    sys.stdout.buffer.write(output)


if __name__ == "__main__":
    _main()
