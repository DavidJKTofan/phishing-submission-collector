-- Drop the table if it exists (useful for re-deployments)
DROP TABLE IF EXISTS reports;

-- Create the table for storing user reports
CREATE TABLE reports (
    id TEXT PRIMARY KEY,        -- UUID for each submission
    name TEXT NOT NULL,         -- Name of the report
    category TEXT NOT NULL,     -- Category of the report
    source TEXT NOT NULL,       -- Source of the threat
    url TEXT NOT NULL,          -- URL being reported
    description TEXT,           -- Description of the threat
    urlscan_uuid TEXT,          -- URLScan.io UUID
    virustotal_scan_id TEXT,    -- VirusTotal Scan ID
    cloudflare_scan_uuid TEXT,  -- Cloudflare URLScanner UUID
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP  -- Unix timestamp to store the submission time
);
