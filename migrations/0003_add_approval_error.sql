-- Adds a dedicated column for approval-stage failures (Discord send errors,
-- waitForEvent failures, malformed approval events). These were previously
-- written into cloudflare_list_error, conflating approval-stage errors with
-- Cloudflare One list write errors.

ALTER TABLE reports_v2 ADD COLUMN approval_error TEXT;
