-- Drop the table if it exists (useful for re-deployments)
DROP TABLE IF EXISTS reports_v2;

-- Create the table for storing user reports
CREATE TABLE reports_v2 (
    id TEXT PRIMARY KEY,                                                                                -- UUID for each submission
    name TEXT NOT NULL CHECK(length(name) BETWEEN 2 AND 100),                                           -- Name of the report
    category TEXT NOT NULL CHECK(category IN ('Phishing', 'Crypto Scam', 'Malware', 'Spam', 'Other')),  -- Category of the report
    source TEXT NOT NULL CHECK(length(source) BETWEEN 2 AND 100),                                       -- Source of the threat
    url TEXT NOT NULL,                                                                                  -- URL being reported
    description TEXT CHECK(length(description) <= 500),                                                 -- Description of the threat
    urlscan_uuid TEXT,                                                                                  -- URLScan.io UUID
    virustotal_scan_id TEXT,                                                                            -- VirusTotal Scan ID
    ipqs_scan TEXT,                                                                                     -- IPQualityScore Scan
    cloudflare_scan_uuid TEXT,                                                                          -- Cloudflare URLScanner UUID
    api_errors TEXT,                                                                                    -- API Errors
    submission_success BOOLEAN DEFAULT TRUE,                                                            -- Submission Success
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,                                                       -- Unix timestamp to store the submission time in Coordinated Universal Time (UTC)
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX idx_reports_category ON reports_v2(category);
CREATE INDEX idx_reports_timestamp ON reports_v2(timestamp);
CREATE INDEX idx_reports_url ON reports_v2(url);