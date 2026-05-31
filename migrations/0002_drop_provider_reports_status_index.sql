-- Drop the unused (provider, status) index on provider_reports.
-- The Worker reads provider_reports only by report_id (the PRIMARY KEY prefix),
-- so this composite index is never used by a query path. Idempotent and safe on
-- fresh databases (no such index) and existing ones (drops it). Same rationale as
-- the historical 003_drop_unused_indexes.sql.
DROP INDEX IF EXISTS idx_provider_reports_status;
