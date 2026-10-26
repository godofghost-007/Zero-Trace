"""Evaluate the Guard detector deterministically or against a live Guard.

Deterministic mode is the default and needs no model provider. Live mode sends
the labeled corpus to a loopback-only Guard instance, so it requires a Guard
BFF key and a configured provider. It is deliberately opt-in because each case
can consume provider tokens.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.guard_eval import (  # noqa: E402
    ATTACK_CASES,
    BENIGN_CASES,
    GuardCase,
    evaluate_detector,
)

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _key(args: argparse.Namespace) -> str:
    if args.api_key_file:
        value = Path(args.api_key_file).read_text("utf-8").strip()
    else:
        value = os.environ.get(args.api_key_env, "").strip()
    if not value:
        raise ValueError(
            f"Guard API key is required (set {args.api_key_env} or --api-key-file)"
        )
    return value


def _post_guard(
    guard_url: str,
    api_key: str,
    body: dict[str, object],
    timeout: int,
) -> tuple[int, dict[str, object]]:
    request = Request(
        guard_url.rstrip("/") + "/v1/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-API-Key": api_key,
            "User-Agent": "ZeroTrace-Guard-Eval/1",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = response.read(1_048_577)
            status = response.status
    except HTTPError as error:
        payload = error.read(1_048_577)
        status = error.code
    except (URLError, TimeoutError, OSError) as error:
        return 0, {
            "error": {
                "code": "transport_error",
                "message": str(error)[:200],
            }
        }
    if len(payload) > 1_048_576:
        return status, {"error": {"code": "response_too_large"}}
    try:
        parsed = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return status, {"error": {"code": "invalid_response"}}
    return status, parsed if isinstance(parsed, dict) else {}


def _error_code(payload: dict[str, object]) -> str:
    error = payload.get("error")
    if isinstance(error, dict):
        code = error.get("code")
        if isinstance(code, str):
            return code
    return ""


def evaluate_live(
    *,
    cases: tuple[GuardCase, ...],
    guard_url: str,
    api_key: str,
    model: str,
    upstream: str | None = None,
    timeout: int = 60,
) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    true_positive = false_positive = true_negative = false_negative = 0
    errors = 0
    for case in cases:
        body: dict[str, object] = {
            "model": model,
            "messages": [{"role": "user", "content": case.text}],
            "temperature": 0,
            "max_tokens": 32,
        }
        if upstream:
            body["upstream"] = upstream
        status, payload = _post_guard(guard_url, api_key, body, timeout)
        code = _error_code(payload)
        blocked = status == 400
        allowed = status == 200
        if status == 0 or not (blocked or allowed):
            outcome = "error"
            errors += 1
        elif case.attack and blocked:
            outcome = "true_positive"
            true_positive += 1
        elif case.attack and allowed:
            outcome = "false_negative"
            false_negative += 1
        elif not case.attack and allowed:
            outcome = "true_negative"
            true_negative += 1
        else:
            outcome = "false_positive"
            false_positive += 1
        rows.append(
            {
                "caseId": case.case_id,
                "category": case.category,
                "expected": "attack" if case.attack else "benign",
                "httpStatus": status,
                "guardCode": code,
                "outcome": outcome,
            }
        )

    decided = true_positive + false_positive + true_negative + false_negative
    precision = (
        true_positive / (true_positive + false_positive)
        if true_positive + false_positive
        else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative)
        if true_positive + false_negative
        else 0.0
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    false_positive_rate = (
        false_positive / (false_positive + true_negative)
        if false_positive + true_negative
        else 0.0
    )
    return {
        "mode": "live",
        "guardUrl": guard_url,
        "model": model,
        "cases": rows,
        "corpus": {
            "total": len(cases),
            "attacks": sum(1 for case in cases if case.attack),
            "benign": sum(1 for case in cases if not case.attack),
        },
        "metrics": {
            "decided": decided,
            "errors": errors,
            "errorRate": errors / len(cases) if cases else 0.0,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "falsePositiveRate": false_positive_rate,
        },
        "confusionMatrix": {
            "truePositive": true_positive,
            "falsePositive": false_positive,
            "trueNegative": true_negative,
            "falseNegative": false_negative,
        },
        "limitations": [
            "Live evaluation depends on the provider and model configured for Guard.",
            "HTTP 400 is treated as a Guard block; provider 4xx/5xx responses are errors.",
            "The synthetic corpus is not a representative adversarial benchmark.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("deterministic", "live"), default="deterministic")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--guard-url", default="http://127.0.0.1:8766")
    parser.add_argument("--model", default="")
    parser.add_argument("--upstream", default=None)
    parser.add_argument("--api-key-env", default="ZEROTRACE_GUARD_BFF_API_KEY")
    parser.add_argument("--api-key-file")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    if args.mode == "deterministic":
        report = evaluate_detector()
        output = args.output or (
            PROJECT_ROOT / "tasks" / "evidence" / "guard-evaluation.json"
        )
    else:
        parts = urlsplit(args.guard_url)
        if parts.hostname not in LOOPBACK_HOSTS or parts.scheme != "http":
            print("live Guard URL must be an http loopback URL", file=sys.stderr)
            return 2
        if not args.model.strip():
            print("--model is required in live mode", file=sys.stderr)
            return 2
        if not 1 <= args.timeout <= 300:
            print("--timeout must be between 1 and 300", file=sys.stderr)
            return 2
        cases = ATTACK_CASES + BENIGN_CASES
        if args.limit > 0:
            cases = cases[: args.limit]
        try:
            api_key = _key(args)
        except (OSError, ValueError) as error:
            print(str(error), file=sys.stderr)
            return 2
        report = evaluate_live(
            cases=cases,
            guard_url=args.guard_url,
            api_key=api_key,
            model=args.model.strip(),
            upstream=args.upstream,
            timeout=args.timeout,
        )
        output = args.output or (
            PROJECT_ROOT / "tasks" / "evidence" / "guard-evaluation-live.json"
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report["metrics"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
