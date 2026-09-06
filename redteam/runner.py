"""
Attack runner: loads the attack library, plays each case's turns against
a target over HTTP (treating the target as a black box, the way a real
engagement would), scores the final response, and returns structured
results.

Target contract expected (matches demo_app/app.py):
  POST {target}/chat       {"session_id": str, "message": str} -> {"reply": str}
  POST {target}/summarize  {"session_id": str, "document": str} -> {"reply": str}

Pointing this at a different app just means writing a thin adapter with
the same two calls -- see README.md "Testing your own app".
"""

from __future__ import annotations

import datetime
import time
from pathlib import Path

import requests
import yaml

from redteam.detectors import run_detector
from redteam.severity import rate_severity

DEFAULT_LIBRARY_PATH = Path(__file__).resolve().parent.parent / "attacks" / "library.yaml"


def load_attacks(path: Path = DEFAULT_LIBRARY_PATH) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        cases = yaml.safe_load(f)
    if not isinstance(cases, list):
        raise ValueError(f"Expected a YAML list of attack cases in {path}")
    return cases


def _play_case(target: str, case: dict, session, timeout: float) -> str:
    session_id = f"redteam-{case['id']}"
    channel = case["channel"]
    last_reply = ""
    for step in case["steps"]:
        if channel == "chat":
            resp = session.post(
                f"{target}/chat",
                json={"session_id": session_id, "message": step["message"]},
                timeout=timeout,
            )
        elif channel == "summarize":
            resp = session.post(
                f"{target}/summarize",
                json={"session_id": session_id, "document": step["document"]},
                timeout=timeout,
            )
        else:
            raise ValueError(f"Unknown channel '{channel}' in case {case['id']}")
        resp.raise_for_status()
        last_reply = resp.json().get("reply", "")
    return last_reply


def run_suite(target: str, cases: list[dict] | None = None, timeout: float = 30.0, delay: float = 0.0) -> dict:
    cases = cases if cases is not None else load_attacks()
    session = requests.Session()
    results = []

    for case in cases:
        try:
            reply = _play_case(target, case, session, timeout)
            error = None
        except requests.RequestException as exc:
            reply = ""
            error = str(exc)

        if error:
            outcome = {"success": False, "evidence": f"request error: {error}"}
        else:
            outcome = run_detector(case["check"], reply)

        severity = rate_severity(case["check"], outcome["success"], bounded=case.get("bounded", False))

        results.append(
            {
                "id": case["id"],
                "category": case["category"],
                "owasp": case.get("owasp", "n/a"),
                "technique": case["technique"],
                "description": case.get("description", "").strip(),
                "channel": case["channel"],
                "check": case["check"],
                "final_reply": reply,
                "success": outcome["success"],
                "evidence": outcome["evidence"],
                "severity": severity,
                "error": error,
            }
        )
        if delay:
            time.sleep(delay)

    return {
        "target": target,
        "run_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total": len(results),
        "findings": [r for r in results if r["success"]],
        "results": results,
    }
