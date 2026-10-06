"""Cadeia de custódia: registro append-only de eventos sobre a evidência."""

import getpass
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def now() -> datetime:
    return datetime.now(timezone.utc).astimezone()


@dataclass
class CustodyEvent:
    timestamp: str
    action: str
    examiner: str
    details: str = ""
    sha256: str = ""


@dataclass
class ChainOfCustody:
    evidence: str
    examiner: str = field(default_factory=getpass.getuser)
    events: list[CustodyEvent] = field(default_factory=list)

    def record(self, action: str, details: str = "", sha256: str = "") -> CustodyEvent:
        event = CustodyEvent(
            timestamp=now().isoformat(timespec="seconds"),
            action=action,
            examiner=self.examiner,
            details=details,
            sha256=sha256,
        )
        self.events.append(event)
        return event

    def save(self, path: Path) -> None:
        payload = {
            "evidence": self.evidence,
            "examiner": self.examiner,
            "events": [asdict(e) for e in self.events],
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "ChainOfCustody":
        payload = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            evidence=payload["evidence"],
            examiner=payload["examiner"],
            events=[CustodyEvent(**e) for e in payload["events"]],
        )
