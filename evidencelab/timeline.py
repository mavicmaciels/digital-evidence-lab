"""Linha do tempo unificada: eventos do e-mail + eventos da cadeia de custódia."""

from dataclasses import dataclass
from datetime import datetime, timezone

from evidencelab.custody import ChainOfCustody
from evidencelab.email_analysis import EmailAnalysis


@dataclass
class TimelineEntry:
    timestamp: datetime
    source: str  # "e-mail" ou "custódia"
    description: str


def build_timeline(analysis: EmailAnalysis, custody: ChainOfCustody) -> list[TimelineEntry]:
    entries: list[TimelineEntry] = []
    if analysis.date:
        entries.append(TimelineEntry(analysis.date, "e-mail", "Data declarada no cabeçalho Date"))
    for hop in analysis.hops:
        if hop.timestamp:
            origin = hop.from_host or "?"
            if hop.ip and hop.ip not in origin:
                origin += f" [{hop.ip}]"
            entries.append(
                TimelineEntry(hop.timestamp, "e-mail", f"Salto {hop.index}: {origin} → {hop.by_host}")
            )
    for event in custody.events:
        entries.append(
            TimelineEntry(datetime.fromisoformat(event.timestamp), "custódia", event.action)
        )
    for entry in entries:
        if entry.timestamp.tzinfo is None:
            entry.timestamp = entry.timestamp.replace(tzinfo=timezone.utc)
        entry.timestamp = entry.timestamp.astimezone(timezone.utc)
    return sorted(entries, key=lambda e: e.timestamp)
