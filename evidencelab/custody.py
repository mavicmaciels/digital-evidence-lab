"""Cadeia de custódia: registro append-only com encadeamento de hashes.

Cada evento guarda o hash do evento anterior (`prev_hash`) e o seu próprio
(`event_hash`). Uma edição posterior no arquivo JSON quebra o encadeamento e é
detectada por `verify_chain()`. Isso evidencia alterações acidentais ou ingênuas,
mas não é assinatura digital: quem controla o arquivo pode recalcular a cadeia
inteira. Para valor probatório, combine com assinatura/carimbo de tempo externos.
"""

import getpass
import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_examiner() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "desconhecido"


@dataclass
class CustodyEvent:
    timestamp: str  # ISO 8601 em UTC
    action: str
    examiner: str
    details: str = ""
    sha256: str = ""
    prev_hash: str = GENESIS
    event_hash: str = ""

    def compute_hash(self) -> str:
        data = asdict(self)
        data.pop("event_hash")
        canonical = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class ChainOfCustody:
    evidence: str
    examiner: str = field(default_factory=default_examiner)
    events: list[CustodyEvent] = field(default_factory=list)
    path: Path | None = None  # se definido, cada registro é persistido imediatamente

    def record(self, action: str, details: str = "", sha256: str = "") -> CustodyEvent:
        event = CustodyEvent(
            timestamp=utc_now(),
            action=action,
            examiner=self.examiner,
            details=details,
            sha256=sha256,
            prev_hash=self.events[-1].event_hash if self.events else GENESIS,
        )
        event.event_hash = event.compute_hash()
        self.events.append(event)
        if self.path:
            self.save(self.path)
        return event

    def verify_chain(self) -> bool:
        prev = GENESIS
        for event in self.events:
            if event.prev_hash != prev or event.compute_hash() != event.event_hash:
                return False
            prev = event.event_hash
        return True

    def initial_hash(self) -> str | None:
        return next((e.sha256 for e in self.events if e.action == "Hash inicial" and e.sha256), None)

    def save(self, path: Path) -> None:
        payload = {
            "evidence": self.evidence,
            "examiner": self.examiner,
            "events": [asdict(e) for e in self.events],
        }
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: Path) -> "ChainOfCustody":
        payload = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            evidence=str(payload["evidence"]),
            examiner=str(payload["examiner"]),
            events=[CustodyEvent(**e) for e in payload["events"]],
            path=path,
        )
