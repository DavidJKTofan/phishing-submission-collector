-- Add human approval and Cloudflare One List tracking fields.
ALTER TABLE reports_v2 ADD COLUMN normalized_hostname TEXT;
ALTER TABLE reports_v2 ADD COLUMN workflow_instance_id TEXT;
ALTER TABLE reports_v2 ADD COLUMN approval_status TEXT CHECK(approval_status IN ('pending', 'approved', 'denied', 'expired', 'workflow_failed'));
ALTER TABLE reports_v2 ADD COLUMN approval_actor TEXT;
ALTER TABLE reports_v2 ADD COLUMN approval_decided_at DATETIME;
ALTER TABLE reports_v2 ADD COLUMN cloudflare_list_status TEXT CHECK(cloudflare_list_status IN ('not_started', 'added', 'skipped_duplicate', 'failed'));
ALTER TABLE reports_v2 ADD COLUMN cloudflare_list_error TEXT;
