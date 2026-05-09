-- Create the table for storing user reports
CREATE TABLE IF NOT EXISTS reports_v2 (
    id TEXT PRIMARY KEY,                                                                                -- UUID for each submission
    name TEXT NOT NULL CHECK(length(name) BETWEEN 2 AND 100),                                           -- Name of the report
    category TEXT NOT NULL CHECK(category IN ('Phishing', 'Crypto Scam', 'Malware', 'Spam', 'Other')),  -- Category of the report
    source TEXT NOT NULL CHECK(source IN ('Email', 'SMS', 'Social Media', 'Website', 'Other')),         -- Source of the threat
    url TEXT NOT NULL,                                                                                  -- URL being reported
    description TEXT CHECK(length(description) <= 500),                                                 -- Description of the threat
    urlscan_uuid TEXT,                                                                                  -- URLScan.io UUID
    virustotal_scan_id TEXT,                                                                            -- VirusTotal Scan ID
    ipqs_scan TEXT,                                                                                     -- IPQualityScore Scan
    cloudflare_scan_uuid TEXT,                                                                          -- Cloudflare URLScanner UUID
    api_errors TEXT,                                                                                    -- API Errors
    submission_success BOOLEAN DEFAULT TRUE,                                                            -- Submission Success
    normalized_hostname TEXT,                                                                           -- Hostname extracted from submitted URL/domain
    workflow_instance_id TEXT,                                                                          -- Cloudflare Workflow instance ID for approval flow
    approval_status TEXT DEFAULT 'pending' CHECK(approval_status IN ('pending', 'approved', 'denied', 'expired', 'workflow_failed')),
    approval_actor TEXT,                                                                                -- Discord user that made the approval decision
    approval_decided_at DATETIME,                                                                       -- Approval decision timestamp in UTC
    cloudflare_list_status TEXT DEFAULT 'not_started' CHECK(cloudflare_list_status IN ('not_started', 'added', 'skipped_duplicate', 'failed')),
    cloudflare_list_error TEXT,                                                                         -- Last Cloudflare One List write error, if any
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,                                                       -- Unix timestamp to store the submission time in Coordinated Universal Time (UTC)
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
);
