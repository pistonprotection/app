-- PistonProtection ClickHouse Database Schema
-- Event storage for DDoS protection analytics

-- Create database
CREATE DATABASE IF NOT EXISTS pistonprotection;

-- Use the database
USE pistonprotection;

-- ============================================================================
-- Packet Events Table - Raw packet-level events (high volume)
-- ============================================================================
CREATE TABLE IF NOT EXISTS packet_events (
    timestamp DateTime64(9, 'UTC'),
    event_date Date MATERIALIZED toDate(timestamp),

    -- Source information
    source_ip IPv6,
    source_port UInt16,
    destination_ip IPv6,
    destination_port UInt16,

    -- Packet details
    protocol Enum8('TCP' = 1, 'UDP' = 2, 'ICMP' = 3, 'OTHER' = 0),
    packet_size UInt32,

    -- Action taken
    action Enum8('ALLOW' = 1, 'DROP' = 2, 'CHALLENGE' = 3, 'RATE_LIMIT' = 4),
    drop_reason LowCardinality(String),

    -- Backend info
    backend_id String,
    worker_id String,

    -- GeoIP data
    country_code LowCardinality(String),
    asn UInt32,
    asn_org LowCardinality(String),

    -- Additional metadata
    rule_id String DEFAULT '',
    fingerprint String DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(event_date)
ORDER BY (backend_id, timestamp, source_ip)
TTL event_date + INTERVAL 7 DAY
SETTINGS index_granularity = 8192;

-- ============================================================================
-- Attack Events Table - Detected attack patterns
-- ============================================================================
CREATE TABLE IF NOT EXISTS attack_events (
    timestamp DateTime64(3, 'UTC'),
    event_date Date MATERIALIZED toDate(timestamp),

    -- Attack identification
    attack_id UUID,
    attack_type LowCardinality(String),
    severity Enum8('LOW' = 1, 'MEDIUM' = 2, 'HIGH' = 3, 'CRITICAL' = 4),

    -- Target information
    backend_id String,
    target_ip IPv6,
    target_port UInt16,

    -- Attack metrics
    packets_per_second Float64,
    bytes_per_second Float64,
    unique_sources UInt32,

    -- Geographic distribution
    top_countries Array(Tuple(String, UInt32)),
    top_asns Array(Tuple(UInt32, String, UInt32)),

    -- Duration
    start_time DateTime64(3, 'UTC'),
    end_time Nullable(DateTime64(3, 'UTC')),

    -- Mitigation
    mitigation_applied LowCardinality(String),
    blocked_percentage Float32
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(event_date)
ORDER BY (backend_id, timestamp, attack_id)
TTL event_date + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- ============================================================================
-- Traffic Statistics - Aggregated traffic data (1-minute buckets)
-- ============================================================================
CREATE TABLE IF NOT EXISTS traffic_stats (
    timestamp DateTime,
    event_date Date MATERIALIZED toDate(timestamp),

    -- Identifiers
    backend_id String,
    worker_id String,

    -- Packet counts
    total_packets UInt64,
    allowed_packets UInt64,
    dropped_packets UInt64,
    challenged_packets UInt64,
    rate_limited_packets UInt64,

    -- Byte counts
    total_bytes UInt64,
    allowed_bytes UInt64,
    dropped_bytes UInt64,

    -- Connection stats
    active_connections UInt32,
    new_connections UInt32,
    closed_connections UInt32,

    -- Protocol breakdown
    tcp_packets UInt64,
    udp_packets UInt64,
    icmp_packets UInt64,
    other_packets UInt64,

    -- Unique counts
    unique_ips UInt32,
    unique_asns UInt16,
    unique_countries UInt16
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(event_date)
ORDER BY (backend_id, worker_id, timestamp)
TTL event_date + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ============================================================================
-- IP Reputation Table - Tracked IPs and their scores
-- ============================================================================
CREATE TABLE IF NOT EXISTS ip_reputation (
    ip IPv6,
    updated_at DateTime DEFAULT now(),

    -- Reputation scoring
    reputation_score Float32,
    threat_level Enum8('CLEAN' = 0, 'SUSPICIOUS' = 1, 'MALICIOUS' = 2, 'BLOCKED' = 3),

    -- Historical data
    first_seen DateTime,
    last_seen DateTime,
    total_requests UInt64,
    blocked_requests UInt64,

    -- Behavior indicators
    is_proxy UInt8,
    is_vpn UInt8,
    is_tor UInt8,
    is_datacenter UInt8,

    -- Geographic
    country_code LowCardinality(String),
    asn UInt32,
    asn_org LowCardinality(String),

    -- Block info
    blocked_until Nullable(DateTime),
    block_reason LowCardinality(String)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY ip
SETTINGS index_granularity = 8192;

-- ============================================================================
-- Rule Performance Table - How rules are performing
-- ============================================================================
CREATE TABLE IF NOT EXISTS rule_performance (
    timestamp DateTime,
    event_date Date MATERIALIZED toDate(timestamp),

    -- Rule identification
    rule_id String,
    rule_name String,
    rule_type LowCardinality(String),

    -- Backend
    backend_id String,

    -- Performance metrics
    evaluations UInt64,
    matches UInt64,
    false_positives UInt64,

    -- Timing
    avg_evaluation_time_us Float64,
    p99_evaluation_time_us Float64,

    -- Impact
    packets_allowed UInt64,
    packets_blocked UInt64,
    bytes_allowed UInt64,
    bytes_blocked UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(event_date)
ORDER BY (backend_id, rule_id, timestamp)
TTL event_date + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ============================================================================
-- OpenTelemetry Traces - For service tracing
-- ============================================================================
CREATE TABLE IF NOT EXISTS otel_traces (
    Timestamp DateTime64(9) CODEC(Delta, ZSTD(1)),
    TraceId String CODEC(ZSTD(1)),
    SpanId String CODEC(ZSTD(1)),
    ParentSpanId String CODEC(ZSTD(1)),
    TraceState String CODEC(ZSTD(1)),
    SpanName LowCardinality(String) CODEC(ZSTD(1)),
    SpanKind LowCardinality(String) CODEC(ZSTD(1)),
    ServiceName LowCardinality(String) CODEC(ZSTD(1)),
    ResourceAttributes Map(LowCardinality(String), String) CODEC(ZSTD(1)),
    ScopeName String CODEC(ZSTD(1)),
    ScopeVersion String CODEC(ZSTD(1)),
    SpanAttributes Map(LowCardinality(String), String) CODEC(ZSTD(1)),
    Duration Int64 CODEC(ZSTD(1)),
    StatusCode LowCardinality(String) CODEC(ZSTD(1)),
    StatusMessage String CODEC(ZSTD(1)),
    Events Nested (
        Timestamp DateTime64(9),
        Name LowCardinality(String),
        Attributes Map(LowCardinality(String), String)
    ) CODEC(ZSTD(1)),
    Links Nested (
        TraceId String,
        SpanId String,
        TraceState String,
        Attributes Map(LowCardinality(String), String)
    ) CODEC(ZSTD(1)),
    INDEX idx_trace_id TraceId TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_service ServiceName TYPE bloom_filter(0.01) GRANULARITY 1
)
ENGINE = MergeTree()
PARTITION BY toDate(Timestamp)
ORDER BY (ServiceName, SpanName, toUnixTimestamp(Timestamp), TraceId)
TTL toDateTime(Timestamp) + INTERVAL 7 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- ============================================================================
-- OpenTelemetry Logs - For centralized logging
-- ============================================================================
CREATE TABLE IF NOT EXISTS otel_logs (
    Timestamp DateTime64(9) CODEC(Delta, ZSTD(1)),
    TraceId String CODEC(ZSTD(1)),
    SpanId String CODEC(ZSTD(1)),
    TraceFlags UInt32 CODEC(ZSTD(1)),
    SeverityText LowCardinality(String) CODEC(ZSTD(1)),
    SeverityNumber Int32 CODEC(ZSTD(1)),
    ServiceName LowCardinality(String) CODEC(ZSTD(1)),
    Body String CODEC(ZSTD(1)),
    ResourceSchemaUrl String CODEC(ZSTD(1)),
    ResourceAttributes Map(LowCardinality(String), String) CODEC(ZSTD(1)),
    ScopeSchemaUrl String CODEC(ZSTD(1)),
    ScopeName String CODEC(ZSTD(1)),
    ScopeVersion String CODEC(ZSTD(1)),
    ScopeAttributes Map(LowCardinality(String), String) CODEC(ZSTD(1)),
    LogAttributes Map(LowCardinality(String), String) CODEC(ZSTD(1)),
    INDEX idx_trace_id TraceId TYPE bloom_filter(0.001) GRANULARITY 1,
    INDEX idx_service ServiceName TYPE bloom_filter(0.01) GRANULARITY 1,
    INDEX idx_body Body TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 1
)
ENGINE = MergeTree()
PARTITION BY toDate(Timestamp)
ORDER BY (ServiceName, SeverityNumber, toUnixTimestamp(Timestamp))
TTL toDateTime(Timestamp) + INTERVAL 7 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

-- ============================================================================
-- Materialized Views for Real-time Analytics
-- ============================================================================

-- Hourly traffic aggregation
CREATE MATERIALIZED VIEW IF NOT EXISTS traffic_hourly_mv
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (backend_id, hour)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    backend_id,
    sum(total_packets) AS total_packets,
    sum(allowed_packets) AS allowed_packets,
    sum(dropped_packets) AS dropped_packets,
    sum(total_bytes) AS total_bytes,
    sum(allowed_bytes) AS allowed_bytes,
    sum(dropped_bytes) AS dropped_bytes
FROM traffic_stats
GROUP BY backend_id, hour;

-- Daily unique IPs per backend
CREATE MATERIALIZED VIEW IF NOT EXISTS unique_ips_daily_mv
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (backend_id, day)
AS SELECT
    toDate(timestamp) AS day,
    backend_id,
    uniqState(source_ip) AS unique_ips
FROM packet_events
GROUP BY backend_id, day;

-- ============================================================================
-- Grants for service users
-- ============================================================================
-- Note: Users are created via environment variables, grants applied here

GRANT SELECT ON pistonprotection.* TO grafana;
GRANT INSERT ON pistonprotection.* TO otel;
GRANT SELECT ON pistonprotection.* TO otel;
