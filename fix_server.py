with open('app/dashboard/server.py', 'rb') as f:
    content = f.read()

old_func = (
    b'def _authenticate(\n'
    b'    headers: dict[str, str],\n'
    b'    required_roles: tuple[str, ...] = ("viewer", "operator", "admin"),\n'
    b') -> Principal:\n'
    b'    """Authenticate via API key header."""\n'
    b'    api_key = headers.get("X-API-Key", "")\n'
    b'    if not api_key or not api_key.strip():\n'
    b'        raise AuthorizationError("Authentication required", 401)\n'
    b'\n'
    b'    # The dashboard API key is shared with the recon/intel/guard modules.\n'
    b'    # In production this would be validated against a user store.\n'
    b'    # For the MVP, any non-empty key is accepted as a viewer.\n'
    b'    return Principal(subject="dashboard-viewer", role="viewer")'
)

new_func = (
    b'    def _authenticate(\n'
    b'        self,\n'
    b'        headers: dict[str, str],\n'
    b'    ) -> Principal:\n'
    b'        """Authenticate via API key header."""\n'
    b'        if self.config.require_api_key:\n'
    b'            if not x_api_key or not x_api_key.strip():\n'
    b'                raise GuardError("API key is required", 401)\n'
    b'            expected_digest = self.config.api_key_digest\n'
    b'            secret = self.config.api_key_secret.encode("utf-8")\n'
    b'            actual_digest = hmac.new(\n'
    b'                secret, x_api_key.encode("utf-8"), hashlib.sha256\n'
    b'            ).hexdigest()\n'
    b'            if not hmac.compare_digest(actual_digest, expected_digest):\n'
    b'                raise GuardError("invalid API key", 401)'
)

if old_func in content:
    content = content.replace(old_func, new_func)
    with open('app/dashboard/server.py', 'wb') as f:
        f.write(content)
    print('Replaced successfully')
else:
    print('Old string not found')