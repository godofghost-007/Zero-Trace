# Backup and restore

ZeroTrace uses encrypted, verifiable backups. The backup key is separate from
the database and must not be stored on the backup host.

## Formats

- Inner manifest: `zerotrace-backup-v1` with kind, source, byte count, SHA-256,
  and timestamp.
- Outer envelope: `zerotrace-backup-v2`, Fernet-encrypted, with an outer
  manifest containing the ciphertext size and SHA-256.
- Encrypted files use `.ztb`; the outer manifest is `.ztb.manifest.json`.

A restore verifies the outer checksum, decrypts and verifies the inner checksum,
and only then touches the target. A tampered or wrong-key backup is rejected.

## Key handling

```bash
# Generate once, then store outside the backup host (password manager or KMS).
python -m scripts.backup_database generate-key
export ZEROTRACE_BACKUP_KEY='...'
```

Use `--key-file` or `--key-env` when the key comes from a secret mount. Do not
put the key in `.env.production` on the same host as the database if the threat
model includes host compromise.

Key rotation:

1. Generate a new key.
2. Re-encrypt the newest verified backup with the new key and keep the old key
   available for older backups.
3. Update the secret mount and restart the backup job.
4. Retain the old key until the retention window has expired.
5. Record the rotation in the change log.

## SQLite demo

```bash
python -m scripts.backup_database backup-sqlite \
  --source data/live-engine.sqlite3 --output backups/live.ztb
python -m scripts.backup_database verify --backup backups/live.ztb
python -m scripts.backup_database restore-sqlite \
  --backup backups/live.ztb --target data/live-engine.sqlite3 --yes
```

The restore keeps a pre-restore copy unless `--no-pre-restore` is supplied.

## PostgreSQL

Use the Docker path when `pg_dump` and `pg_restore` are not installed on the
host. The container must be the database container, not the application.

```bash
python -m scripts.backup_database backup-postgres \
  --container frontend-postgres-1 --database zerotrace --user zerotrace \
  --output backups/postgres.ztb --offhost-dir /mnt/offhost/zerotrace

python -m scripts.backup_database verify --backup backups/postgres.ztb

python -m scripts.backup_database restore-postgres \
  --container frontend-postgres-1 --database zerotrace --user zerotrace \
  --backup backups/postgres.ztb --yes
```

The restore uses `pg_restore --clean --if-exists` and creates a pre-restore
custom-format dump beside the decrypted backup.

## Retention

`prune_backups` keeps the newest `--keep-minimum` files even when they are older
than `--retain-days`. This prevents a long outage from deleting the only
recoverable copy.

```bash
python -m scripts.backup_database prune \
  --directory /mnt/offhost/zerotrace --retain-days 30 --keep-minimum 7
```

Recommended baseline: daily backups, 30-day retention, 7 minimum copies, and
one restore drill per quarter. Adjust only with a written risk decision.

## Evidence

The local PostgreSQL drill is recorded in
`tasks/evidence/postgres-backup-restore.json`. It covers encryption, checksum
verification, destructive deletion, restore, and a measured restore time. It is
not a production VPS or Supabase drill.

## RPO and RTO

- RPO target: 24 hours.
- RTO target: 2 hours, including operator decision time.
- Observed local drill restore: 8.81 seconds for a small synthetic database.

The observed time excludes DNS, TLS, image pulls, provider recovery, and the
time to obtain the off-host key. Do not present it as a production RTO.
