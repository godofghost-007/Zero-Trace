"""Generate a BFF-to-Guard API key and its HMAC digest.

The generated key is shown once. Put it in the BFF's Guard client secret
configuration, and put only the digest in Guard's configuration. The digest is
not a password; the Guard HMAC secret remains required.

Example:
    python -m scripts.generate_guard_credentials --secret-env ZEROTRACE_GUARD_API_KEY_SECRET
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--secret-env", default="ZEROTRACE_GUARD_API_KEY_SECRET"
    )
    parser.add_argument(
        "--api-key",
        help="Compute a digest for an existing key instead of generating one.",
    )
    args = parser.parse_args()
    secret = os.environ.get(args.secret_env, "").strip()
    if not secret:
        print(f"{args.secret_env} is required", file=sys.stderr)
        return 2
    key = args.api_key or secrets.token_urlsafe(32)
    if len(key) < 16:
        print("API key must be at least 16 characters", file=sys.stderr)
        return 2
    digest = hmac.new(
        secret.encode("utf-8"), key.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    print(
        json.dumps(
            {
                "apiKey": key,
                "apiKeyDigest": digest,
                "warning": (
                    "Store apiKey in the BFF secret store and apiKeyDigest in "
                    "Guard. Do not commit either value."
                ),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
