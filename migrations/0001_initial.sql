-- users
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    username TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    disabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- roles
CREATE TABLE roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);

-- user_roles
CREATE TABLE user_roles (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- nodes
CREATE TABLE nodes (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    hostname TEXT,
    platform TEXT,
    architecture TEXT,
    agent_version TEXT,
    remote_addr TEXT,
    last_seen_at TEXT,
    connected_at TEXT,
    config_version BIGINT NOT NULL DEFAULT 0,
    applied_config_version BIGINT NOT NULL DEFAULT 0,
    config_status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- credentials
CREATE TABLE credentials (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT,
    last_used_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_credentials_node ON credentials(node_id);
CREATE INDEX idx_credentials_hash ON credentials(secret_hash);

-- routes
CREATE TABLE routes (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL UNIQUE,
    node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    listen_host TEXT,
    listen_port INTEGER,
    hostname TEXT,
    target_host TEXT NOT NULL,
    target_port INTEGER NOT NULL,
    tls_mode TEXT,
    status TEXT NOT NULL DEFAULT 'draft',
    limits TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_routes_node ON routes(node_id);
CREATE INDEX idx_routes_hostname ON routes(hostname);

-- acl_rules
CREATE TABLE acl_rules (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    route_id TEXT REFERENCES routes(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    source_cidr TEXT,
    source_port INTEGER,
    target_host TEXT,
    target_port INTEGER,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_acl_route ON acl_rules(route_id);

-- domains
CREATE TABLE domains (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    hostname TEXT NOT NULL UNIQUE,
    route_id TEXT REFERENCES routes(id) ON DELETE SET NULL,
    tls_mode TEXT,
    certificate_id TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- certificates
CREATE TABLE certificates (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL,
    hostnames TEXT NOT NULL,
    certificate TEXT NOT NULL,
    private_key_encrypted TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- audit_logs
CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    user_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    ip TEXT,
    user_agent TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_audit_created ON audit_logs(created_at);
CREATE INDEX idx_audit_user ON audit_logs(user_id);
