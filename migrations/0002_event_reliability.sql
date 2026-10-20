ALTER TABLE event_outbox
    ADD COLUMN IF NOT EXISTS dead_letter_reason TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'event_outbox_status_check'
    ) THEN
        ALTER TABLE event_outbox
            ADD CONSTRAINT event_outbox_status_check
            CHECK (status IN ('pending', 'processing', 'published', 'failed', 'dead_letter'));
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'event_outbox_attempts_check'
    ) THEN
        ALTER TABLE event_outbox
            ADD CONSTRAINT event_outbox_attempts_check
            CHECK (attempts >= 0);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'event_outbox_schema_version_check'
    ) THEN
        ALTER TABLE event_outbox
            ADD CONSTRAINT event_outbox_schema_version_check
            CHECK (schema_version > 0);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'event_outbox_published_state_check'
    ) THEN
        ALTER TABLE event_outbox
            ADD CONSTRAINT event_outbox_published_state_check
            CHECK ((status = 'published') = (published_at IS NOT NULL));
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS event_outbox_pending_idx
    ON event_outbox (created_at, event_id)
    WHERE status IN ('pending', 'failed');

CREATE TABLE IF NOT EXISTS processed_events (
    consumer_name VARCHAR(128) NOT NULL,
    event_id UUID NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (consumer_name, event_id)
);
