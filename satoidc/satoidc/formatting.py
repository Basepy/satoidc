"""Formatação de valores exibidos nas telas."""

from datetime import datetime, timezone
from typing import Optional

SCOPE_LABELS = {
    "openid": "ID",
    "profile": "Perfil",
    "email": "E-mail",
    "wallet": "Carteira",
}


def fmt_date(value: Optional[datetime]) -> str:
    """dd/mm/aaaa no fuso local do servidor (datas do SQLite vêm em UTC)."""
    if not value:
        return "—"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone().strftime("%d/%m/%Y")


def short(value: Optional[str], head: int = 6, tail: int = 6) -> str:
    """02a1c4…e79f3c — abrevia identificadores longos."""
    if not value:
        return "—"
    if len(value) <= head + tail + 1:
        return value
    return f"{value[:head]}…{value[-tail:]}"


def scope_labels(scope: str) -> list[str]:
    return [SCOPE_LABELS.get(s, s) for s in (scope or "").split()]
