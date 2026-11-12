CREATE TABLE IF NOT EXISTS shadow_apps (
id BIGSERIAL PRIMARY KEY,name TEXT UNIQUE NOT NULL,vendor_name TEXT NOT NULL,domains TEXT[] NOT NULL DEFAULT '{}',
approved BOOLEAN NOT NULL DEFAULT FALSE,category TEXT NOT NULL DEFAULT 'Unclassified',
vendor_score SMALLINT NOT NULL DEFAULT 50 CHECK(vendor_score BETWEEN 0 AND 100),
risk_score SMALLINT NOT NULL DEFAULT 0 CHECK(risk_score BETWEEN 0 AND 100),
risk_level TEXT NOT NULL DEFAULT 'Low' CHECK(risk_level IN ('Critical','High','Moderate','Low')),
first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS telemetry_events (
id BIGSERIAL PRIMARY KEY,app_id BIGINT REFERENCES shadow_apps(id) ON DELETE SET NULL,domain TEXT NOT NULL,
user_id TEXT NOT NULL,department TEXT NOT NULL,event_type TEXT NOT NULL,
data_sensitivity TEXT NOT NULL CHECK(data_sensitivity IN ('public','internal','confidential','restricted')),
bytes_out BIGINT NOT NULL DEFAULT 0 CHECK(bytes_out>=0),occurred_at TIMESTAMPTZ NOT NULL,source TEXT NOT NULL,
risk_score SMALLINT NOT NULL CHECK(risk_score BETWEEN 0 AND 100),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS incidents (
id BIGSERIAL PRIMARY KEY,app_id BIGINT REFERENCES shadow_apps(id) ON DELETE SET NULL,title TEXT NOT NULL,
severity TEXT NOT NULL CHECK(severity IN ('Critical','High','Moderate','Low')),
status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open','Investigating','Contained','Closed')),
description TEXT NOT NULL,risk_score SMALLINT NOT NULL CHECK(risk_score BETWEEN 0 AND 100),
detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),closed_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS remediation_logs (
id BIGSERIAL PRIMARY KEY,incident_id BIGINT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,action TEXT NOT NULL,
approved_by TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Pending approval' CHECK(status IN ('Pending approval','Approved','Rejected','Simulated','Verified')),
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS policy_assessments (
id BIGSERIAL PRIMARY KEY,vendor_name TEXT NOT NULL,risk_score SMALLINT NOT NULL CHECK(risk_score BETWEEN 0 AND 100),
risk_level TEXT NOT NULL,findings JSONB NOT NULL,analysis_type TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS audit_logs (
id BIGSERIAL PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,entity_type TEXT NOT NULL,entity_id TEXT,
details JSONB NOT NULL DEFAULT '{}'::jsonb,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE INDEX IF NOT EXISTS idx_telemetry_time ON telemetry_events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_incident_status ON incidents(status,severity);
CREATE INDEX IF NOT EXISTS idx_apps_risk ON shadow_apps(risk_score DESC);
