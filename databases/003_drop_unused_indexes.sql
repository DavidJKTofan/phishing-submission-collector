-- Drop indexes that are not used by the current Worker query paths.
-- Current reads use the primary-key index on reports_v2.id.
DROP INDEX IF EXISTS idx_reports_category;
DROP INDEX IF EXISTS idx_reports_timestamp;
DROP INDEX IF EXISTS idx_reports_url;
