-- Persist NVD CPE version ranges alongside the CPE criteria.
-- Each entry is [criteria, versionStartIncluding, versionStartExcluding,
-- versionEndIncluding, versionEndExcluding]; bounds may be null.
ALTER TABLE intel_vulnerability_facts
    ADD COLUMN IF NOT EXISTS cpe_ranges JSONB NOT NULL DEFAULT '[]'::jsonb;
