CREATE TABLE traffic_stats (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    node_id TEXT,
    route_id TEXT,
    window_start TEXT NOT NULL,
    window_seconds INTEGER NOT NULL,
    rx_bytes BIGINT NOT NULL DEFAULT 0,
    tx_bytes BIGINT NOT NULL DEFAULT 0,
    connections INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_stats_node ON traffic_stats(node_id, window_start);
CREATE INDEX idx_stats_route ON traffic_stats(route_id, window_start);
