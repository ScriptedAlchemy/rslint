#!/usr/bin/env python3
"""
Shared parity health classification utilities.
"""

from __future__ import annotations


def compute_health_reason(critical: int, high: int, flagged: int) -> tuple[str, str]:
	if critical > 0:
		return "red", "critical backlog is non-zero"
	if high > 0:
		return "yellow", "high backlog is non-zero"
	if flagged > 0:
		return "yellow", "non-critical flagged backlog remains"
	return "green", "no flagged parity backlog"
