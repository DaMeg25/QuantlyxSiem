"""Presentation helpers for the rotation meter and posture colouring."""

from __future__ import annotations

from django import template

register = template.Library()

#: Fraction of the policy interval consumed, mapped to a posture band.
BANDS = (
    (0.75, "fresh"),
    (1.0, "approaching"),
    (1.5, "overdue"),
    (float("inf"), "critical"),
)


@register.filter
def meter_width(pressure) -> float:
    """Bar width as a percentage, capped so an ancient credential stays on screen."""
    try:
        value = float(pressure)
    except (TypeError, ValueError):
        return 0.0
    return round(min(value, 2.0) / 2.0 * 100, 1)


@register.filter
def posture(pressure) -> str:
    try:
        value = float(pressure)
    except (TypeError, ValueError):
        return "unknown"
    for ceiling, name in BANDS:
        if value <= ceiling:
            return name
    return "critical"


@register.filter
def severity_rank(value: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(value, 9)


@register.filter
def humanise_days(value) -> str:
    if value is None:
        return "never"
    try:
        days = int(value)
    except (TypeError, ValueError):
        return str(value)
    if days < 1:
        return "today"
    if days < 60:
        return f"{days}d"
    if days < 730:
        return f"{days // 30}mo"
    return f"{days // 365}y"


@register.filter
def dictvalue(mapping, key):
    try:
        return mapping.get(key)
    except AttributeError:
        return None
