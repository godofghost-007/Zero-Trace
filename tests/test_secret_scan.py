from scripts.scan_secrets import scan_diff, scan_line, scan_text


def test_scanner_flags_common_credentials():
    findings = scan_text(
        "config.env",
        'AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n'
        'OPENAI_API_KEY="sk-abcdefghijklmnopqrstuvwxyz123456"\n'
        "DATABASE_URL=postgresql://user:longpassword@db.example.test/app\n",
    )
    kinds = {item.kind for item in findings}
    assert "aws-access-key" in kinds
    assert "openai-key" in kinds
    assert "postgres-url-password" in kinds
    assert all("longpassword" not in item.preview for item in findings)


def test_scanner_ignores_placeholders_and_empty_values():
    text = (
        "ZEROTRACE_GUARD_PROVIDER_API_KEY=<set-in-secret-manager>\n"
        "CLIENT_SECRET=changeme\n"
        "API_KEY=\n"
        "PASSWORD=example-password\n"
        "TOKEN=${TOKEN_FROM_VAULT}\n"
    )
    assert scan_text("deploy/example.env", text) == []


def test_scanner_only_scans_added_diff_lines():
    diff = (
        "diff --git a/app.env b/app.env\n"
        "--- a/app.env\n"
        "+++ b/app.env\n"
        "@@ -1,2 +1,2 @@\n"
        "-OLD_TOKEN=sk-abcdefghijklmnopqrstuvwxyz123456\n"
        "+NEW_TOKEN=plain-text\n"
        "+AWS_SECRET_ACCESS_KEY=AKIAABCDEFGHIJKLMNOP\n"
    )
    findings = scan_diff(diff)
    assert len(findings) == 1
    assert findings[0].file == "app.env"
    assert findings[0].line == 2
    assert findings[0].kind == "aws-access-key"


def test_scanner_flags_generic_assignment_but_not_short_values():
    assert scan_line("x.env", 1, 'api_key = "abcdefghijklmnop"')
    assert not scan_line("x.env", 1, "api_key = short")
