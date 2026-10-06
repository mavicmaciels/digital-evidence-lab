"""Linha do tempo unificada (UTC): eventos do e-mail + eventos da cadeia de custódia."""

from dataclasses import dataclass
from datetime import datetime, timezone

from evidencelab.custody import ChainOfCustody
from evidencelab.email_analysis import EmailAnalysis


@dataclass
class TimelineEntry:
    timestamp: datetime  # UTC
    source: str  # "e-mail" ou "custódia"
    description: str


def _utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def build_timeline(analysis: EmailAnalysis, custody: ChainOfCustody) -> list[TimelineEntry]:
    entries: list[TimelineEntry] = []
    if analysis.date:
        entries.append(
            TimelineEntry(analysis.date, "e-mail", "Cabeçalho Date (informado pelo remetente; não confiável)")
        )
    for hop in analysis.hops:
        if hop.timestamp:
            origin = hop.from_host or "?"
            if hop.ip and hop.ip not in origin:
                origin += f" [{hop.ip}]"
            entries.append(
                TimelineEntry(hop.timestamp, "e-mail", f"Received {hop.index}: {origin} → {hop.by_host}")
            )
    for event in custody.events:
        entries.append(TimelineEntry(datetime.fromisoformat(event.timestamp), "custódia", event.action))
    for entry in entries:
        entry.timestamp = _utc(entry.timestamp)
    return sorted(entries, key=lambda e: e.timestamp)
