from __future__ import annotations

import os
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from app.recon import (
    AdapterResult,
    InMemoryReconRepository,
    ReconEngine,
    Scope,
    SyntheticAdapter,
)
from app.recon_api import ReconQueue, create_recon_app
from app.security import Principal
from app.target_policy import TargetPolicy, TargetPolicyError, normalize_target


def test_normalize_target_rejects_urls_ports_and_wildcards():
    with pytest.raises(TargetPolicyError):
        normalize_target("https://example.com")
    with pytest.raises(TargetPolicyError):
        normalize_target("example.com:443")
    with pytest.raises(TargetPolicyError):
        normalize_target("*.example.com")
    with pytest.raises(TargetPolicyError):
        normalize_target("localhost")
    with pytest.raises(TargetPolicyError, match="not an IP address"):
        normalize_target("192.0.2.10")


def test_normalize_target_is_case_and_trailing_dot_insensitive():
    assert normalize_target(" Example.COM. ") == "example.com"


def test_allowlist_accepts_exact_host_and_subdomain():
    policy = TargetPolicy(allowlist=("example.com",))
    assert policy.check("example.com") == "example.com"
    assert policy.check("www.example.com") == "www.example.com"
    with pytest.raises(TargetPolicyError, match="not in the allowlist"):
        policy.check("example.net")


def test_denylist_wins_over_allowlist():
    policy = TargetPolicy(
        allowlist=("example.com",), denylist=("admin.example.com",)
    )
    assert policy.check("www.example.com") == "www.example.com"
    with pytest.raises(TargetPolicyError, match="denylist"):
        policy.check("admin.example.com")
    with pytest.raises(TargetPolicyError, match="denylist"):
        policy.check("deep.admin.example.com")


def test_denylist_does_not_match_a_suffix_without_a_label_boundary():
    policy = TargetPolicy(denylist=("example.com",))
    with pytest.raises(TargetPolicyError):
        policy.check("example.com")
    with pytest.raises(TargetPolicyError):
        policy.check("www.example.com")
    # This is a different registrable domain, not a subdomain of example.com.
    assert policy.check("notexample.com") == "notexample.com"


def test_policy_from_env_supports_commas_and_newlines():
    env = {
        "ZEROTRACE_TARGET_ALLOWLIST": "example.com,\nlab.example.test\n",
        "ZEROTRACE_TARGET_DENYLIST": "blocked.example.com",
    }
    with mock.patch.dict(os.environ, env, clear=False):
        policy = TargetPolicy.from_env()
    assert policy.allowlist == ("example.com", "lab.example.test")
    assert policy.denylist == ("blocked.example.com",)
    assert policy.summary() == {
        "allowlistConfigured": True,
        "denylistConfigured": True,
        "allowlistEntries": 2,
        "denylistEntries": 1,
    }


def _queue_with_policy(policy: TargetPolicy) -> ReconQueue:
    repository = InMemoryReconRepository()
    engine = ReconEngine(
        repository,
        {
            "synthetic_inventory_v1": SyntheticAdapter(
                AdapterResult(("lab.example.test",), (), ())
            )
        },
    )
    return ReconQueue(engine, repository, target_policy=policy)


def _scope() -> Scope:
    from datetime import UTC, datetime, timedelta

    return Scope(
        scope_id="scope-policy",
        owner_id="operator-1",
        targets=("lab.example.test",),
        environment="synthetic",
        approved=True,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        profiles=("synthetic_inventory_v1",),
    )


def test_scope_creation_is_rejected_by_server_side_policy():
    queue = _queue_with_policy(TargetPolicy(allowlist=("allowed.example",)))
    client = TestClient(
        create_recon_app(queue, lambda request: Principal("operator-1", "operator"))
    )
    response = client.post(
        "/api/v1/recon/scopes",
        json={
            "scopeId": "scope-denied",
            "targets": ["lab.example.test"],
            "environment": "synthetic",
            "profiles": ["synthetic_inventory_v1"],
        },
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "recon_error"
    assert "allowlist" in response.json()["error"]["message"]


def test_queueing_is_rejected_by_server_side_policy():
    queue = _queue_with_policy(TargetPolicy(denylist=("lab.example.test",)))
    scope = _scope()
    queue.add_scope(scope)
    client = TestClient(
        create_recon_app(queue, lambda request: Principal("operator-1", "operator"))
    )
    response = client.post(
        "/api/v1/recon/scans",
        json={
            "scopeId": scope.scope_id,
            "target": "lab.example.test",
            "profileId": "synthetic_inventory_v1",
        },
    )
    assert response.status_code == 400
    assert "denylist" in response.json()["error"]["message"]
