from backend.mfa import (
    decrypt_secret,
    encrypt_secret,
    generate_key,
    generate_secret,
    provisioning_uri,
    totp,
    verify_totp,
)


def test_rfc6238_sha1_vectors_at_six_digits():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    assert totp(secret, at=59) == "287082"
    assert totp(secret, at=1111111109) == "081804"
    assert verify_totp(secret, "287082", at=59)
    assert not verify_totp(secret, "000000", at=59)
    assert verify_totp(secret, "287082", at=89, window=1)


def test_mfa_secret_is_encrypted_at_rest_and_uri_is_scoped():
    secret = generate_secret()
    key = generate_key()
    encrypted = encrypt_secret(secret, key)

    assert secret not in encrypted
    assert decrypt_secret(encrypted, key) == secret
    uri = provisioning_uri(secret, email="operator@zerotrace.local")
    assert uri.startswith("otpauth://totp/ZeroTrace:operator%40zerotrace.local?")
    assert "secret=" in uri
    assert "issuer=ZeroTrace" in uri
