-- providers: supplier master for enabled/rate-limit; API keys live in .env only
CREATE TABLE IF NOT EXISTS providers (
    id BIGSERIAL PRIMARY KEY,
    code VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    base_url VARCHAR(512),
    enabled BOOLEAN NOT NULL DEFAULT true,
    rate_limit_per_min INT NOT NULL DEFAULT 60,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- lookup_requests: one row per lookup (indicator_value may be hashed for anonymization)
CREATE TABLE IF NOT EXISTS lookup_requests (
    id BIGSERIAL PRIMARY KEY,
    request_id UUID NOT NULL UNIQUE,
    indicator_type VARCHAR(32) NOT NULL,
    indicator_value VARCHAR(2048) NOT NULL,
    user_id VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_lookup_requests_indicator_type_created_at ON lookup_requests(indicator_type, created_at);

-- lookup_results: cache/history per provider
CREATE TABLE IF NOT EXISTS lookup_results (
    id BIGSERIAL PRIMARY KEY,
    lookup_request_id BIGINT NOT NULL REFERENCES lookup_requests(id) ON DELETE CASCADE,
    provider_code VARCHAR(64) NOT NULL,
    raw_response JSONB,
    cached_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ttl_seconds INT NOT NULL DEFAULT 3600,
    UNIQUE(lookup_request_id, provider_code)
);

CREATE INDEX idx_lookup_results_cached_at ON lookup_results(cached_at);

-- audit_logs: no PII/full IP; anonymized fields only
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    request_id UUID,
    action VARCHAR(64) NOT NULL,
    resource_type VARCHAR(64),
    resource_id VARCHAR(128),
    ip_hash VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
