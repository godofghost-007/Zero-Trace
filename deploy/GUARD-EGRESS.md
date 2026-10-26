# Guard egress lockdown

Guard is the only process allowed to hold a model-provider credential. It must
not be able to reach arbitrary destinations even if a prompt, dependency, or
configuration is compromised.

## What is enforced in code

- `HttpGuardTransport` accepts only HTTPS, the exact
  `/v1/chat/completions` path, no query/fragment/userinfo, port 443, and a
  hostname on `ZEROTRACE_GUARD_UPSTREAM_ALLOWLIST`.
- The URL is checked before the network opener is called. A negative test
  asserts a disallowed URL produces zero opener calls.
- Redirects are disabled, so an allowlisted origin cannot bounce the request to
  an arbitrary host.
- `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` are ignored; the provider key
  never goes through an environment-configured proxy.
- The provider key is read server-side from `ZEROTRACE_GUARD_PROVIDER_API_KEY`
  or its `_FILE` form and is never returned to the browser or BFF.
- Guard binds only to `127.0.0.1`, `::1`, or `localhost` and refuses other
  hosts at startup.

This is an application allowlist, not a kernel-level egress guarantee. A
compromised Python process could open a raw socket. Production needs one of the
host controls below.

## Recommended host control: dedicated Guard namespace

Run Guard in its own network namespace with an egress firewall that permits
only DNS and the provider origin. Keep the BFF/engine in a separate namespace.
The BFF should reach Guard through a private socket or a loopback-only sidecar,
not through a public interface.

Example nftables policy for a dedicated Guard namespace:

```nft
table inet zt_guard {
  chain output {
    type filter hook output priority 0; policy drop;
    oif "lo" accept
    ct state established,related accept
    # Replace with the provider's published addresses and resolver.
    ip daddr 203.0.113.10 tcp dport 443 accept
    ip daddr 127.0.0.53 udp dport 53 accept
  }
}
```

Do not put the provider key in the BFF, engine, browser, or compose environment
for the BFF. Only the Guard container gets `.env.guard`.

## Canary test

From inside the Guard namespace, the following must fail:

```sh
python -c "import urllib.request; urllib.request.urlopen('https://example.com', timeout=3)"
```

The allowlisted provider request must still succeed through Guard. Record the
container image digest, namespace/firewall rules, canary output, and reviewer in
`tasks/evidence/`. A unit test alone is not network-level evidence.

## Current compose caveat

The reference `deploy/compose.prod.yaml` currently shares the engine network
namespace so Guard, BFF, and engine can use loopback URLs. That is convenient
but it does not isolate Guard egress. Before production, either:

1. split Guard into its own namespace with the firewall above and give the BFF a
   private Unix-socket/loopback bridge; or
2. keep the shared namespace and explicitly accept the residual risk with a
   documented reviewer signoff.

The first option is the production target. The local preview remains
inspect-only and loopback-only; it is not a public deployment.
