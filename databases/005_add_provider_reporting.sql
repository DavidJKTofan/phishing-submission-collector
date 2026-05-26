-- Store post-approval provider reporting outcomes separately from scanner results.
CREATE TABLE IF NOT EXISTS provider_reports (
    report_id TEXT NOT NULL,
    provider TEXT NOT NULL CHECK(provider IN ('netcraft', 'cloudflare_abuse', 'microsoft_msrc')),
    status TEXT NOT NULL CHECK(status IN ('not_started', 'skipped', 'submitted', 'failed')),
    eligibility_reason TEXT,
    reference_id TEXT,
    http_status INTEGER,
    response_json TEXT,
    error TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (report_id, provider),
    FOREIGN KEY (report_id) REFERENCES reports_v2(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_provider_reports_status ON provider_reports(provider, status);
