import { relations, sql } from "drizzle-orm";
import {
  boolean,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uuid,
  varchar,
  bigint,
  real,
} from "drizzle-orm/pg-core";
import { organization, user } from "./auth-schema";

// Enums for DDoS protection
export const protocolEnum = pgEnum("protocol", [
  "tcp",
  "udp",
  "http",
  "https",
  "quic",
  "minecraft_java",
  "minecraft_bedrock",
]);

export const filterActionEnum = pgEnum("filter_action", [
  "allow",
  "block",
  "rate_limit",
  "challenge",
  "drop",
]);

export const backendStatusEnum = pgEnum("backend_status", [
  "healthy",
  "degraded",
  "unhealthy",
  "unknown",
]);

export const organizationStatusEnum = pgEnum("organization_status", [
  "pre-onboarding",
  "active",
  "suspended",
  "cancelled",
]);

export const loadBalancerAlgorithmEnum = pgEnum("load_balancer_algorithm", [
  "round_robin",
  "least_connections",
  "ip_hash",
  "weighted",
  "random",
]);

export const healthCheckTypeEnum = pgEnum("health_check_type", [
  "tcp",
  "http",
  "minecraft",
  "udp",
]);

export const severityEnum = pgEnum("severity", [
  "low",
  "medium",
  "high",
  "critical",
]);

// Protection organization - extends base organization with DDoS-specific data
export const protectionOrganization = pgTable("protection_organization", {
  organizationId: uuid("organization_id")
    .primaryKey()
    .references(() => organization.id, { onDelete: "cascade" }),
  status: organizationStatusEnum("status").notNull().default("pre-onboarding"),
  bandwidthLimit: bigint("bandwidth_limit", { mode: "number" }).default(1_000_000_000), // 1GB default
  backendsLimit: integer("backends_limit").default(1),
  filtersLimit: integer("filters_limit").default(5),
  bandwidthUsed: bigint("bandwidth_used", { mode: "number" }).default(0),
  lastUsageReset: timestamp("last_usage_reset").defaultNow(),
}).enableRLS();

// Backend servers (protected origin servers)
export const backend = pgTable(
  "backend",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    description: text("description"),
    protocol: protocolEnum("protocol").notNull(),
    status: backendStatusEnum("status").notNull().default("unknown"),
    enabled: boolean("enabled").notNull().default(true),
    // Protection settings
    protectionLevel: integer("protection_level").default(50), // 0-100
    rateLimit: integer("rate_limit"), // requests per second
    rateLimitWindow: integer("rate_limit_window").default(1), // seconds
    // Load balancer settings
    loadBalancerAlgorithm: loadBalancerAlgorithmEnum("load_balancer_algorithm").default("round_robin"),
    stickySessions: boolean("sticky_sessions").default(false),
    stickySessionTtl: integer("sticky_session_ttl").default(3600),
    // Health check settings
    healthCheckType: healthCheckTypeEnum("health_check_type").default("tcp"),
    healthCheckInterval: integer("health_check_interval").default(30),
    healthCheckTimeout: integer("health_check_timeout").default(5),
    healthCheckRetries: integer("health_check_retries").default(3),
    healthCheckPath: text("health_check_path"), // For HTTP health checks
    // Proxy settings
    haproxyProtocol: boolean("haproxy_protocol").notNull().default(false),
    haproxyProtocolVersion: integer("haproxy_protocol_version").default(2),
    // Timestamps
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
    lastHealthCheck: timestamp("last_health_check"),
  },
  (table) => [
    index("backend_organization_id_idx").on(table.organizationId),
    index("backend_status_idx").on(table.status),
  ]
).enableRLS();

// Backend origins (actual server endpoints)
export const backendOrigin = pgTable(
  "backend_origin",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    backendId: uuid("backend_id")
      .notNull()
      .references(() => backend.id, { onDelete: "cascade" }),
    address: text("address").notNull(), // IP or hostname
    port: integer("port").notNull(),
    weight: integer("weight").default(100),
    priority: integer("priority").default(1),
    enabled: boolean("enabled").default(true),
    status: backendStatusEnum("status").default("unknown"),
    // TLS settings
    tlsEnabled: boolean("tls_enabled").default(false),
    tlsVerify: boolean("tls_verify").default(true),
    tlsSni: text("tls_sni"),
    // Connection settings
    maxConnections: integer("max_connections").default(1000),
    connectionTimeout: integer("connection_timeout").default(5000),
    // Timestamps
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
    lastHealthCheck: timestamp("last_health_check"),
    lastHealthCheckMessage: text("last_health_check_message"),
  },
  (table) => [
    index("backend_origin_backend_id_idx").on(table.backendId),
  ]
).enableRLS();

// Domains for backends
export const backendDomain = pgTable(
  "backend_domain",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    backendId: uuid("backend_id")
      .notNull()
      .references(() => backend.id, { onDelete: "cascade" }),
    domain: text("domain").notNull(),
    verified: boolean("verified").default(false),
    verificationToken: text("verification_token"),
    verificationMethod: text("verification_method").default("dns"), // dns, http
    sslEnabled: boolean("ssl_enabled").default(true),
    forceHttps: boolean("force_https").default(true),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    verifiedAt: timestamp("verified_at"),
  },
  (table) => [
    index("backend_domain_backend_id_idx").on(table.backendId),
    index("backend_domain_domain_idx").on(table.domain),
  ]
).enableRLS();

// Filter rules
export const filter = pgTable(
  "filter",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    backendId: uuid("backend_id")
      .references(() => backend.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    description: text("description"),
    protocol: protocolEnum("protocol"),
    action: filterActionEnum("action").notNull(),
    priority: integer("priority").notNull().default(100),
    enabled: boolean("enabled").notNull().default(true),
    // Match conditions
    sourceIps: jsonb("source_ips").$type<string[]>(),
    sourceCidrs: jsonb("source_cidrs").$type<string[]>(),
    sourceCountries: jsonb("source_countries").$type<string[]>(),
    sourceAsns: jsonb("source_asns").$type<number[]>(),
    destPorts: jsonb("dest_ports").$type<number[]>(),
    // L7 specific conditions
    httpMethods: jsonb("http_methods").$type<string[]>(),
    httpPaths: jsonb("http_paths").$type<string[]>(),
    httpHosts: jsonb("http_hosts").$type<string[]>(),
    httpHeaders: jsonb("http_headers").$type<Record<string, string>>(),
    httpUserAgents: jsonb("http_user_agents").$type<string[]>(),
    // Rate limiting
    rateLimit: integer("rate_limit"),
    rateLimitWindow: integer("rate_limit_window"),
    rateLimitBurst: integer("rate_limit_burst"),
    // Time-based activation
    activeFrom: timestamp("active_from"),
    activeTo: timestamp("active_to"),
    activeDays: jsonb("active_days").$type<number[]>(), // 0-6, Sunday-Saturday
    activeHoursStart: integer("active_hours_start"), // 0-23
    activeHoursEnd: integer("active_hours_end"),
    // Statistics
    matchCount: bigint("match_count", { mode: "number" }).default(0),
    lastMatch: timestamp("last_match"),
    // Timestamps
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => [
    index("filter_organization_id_idx").on(table.organizationId),
    index("filter_backend_id_idx").on(table.backendId),
    index("filter_priority_idx").on(table.priority),
  ]
).enableRLS();

// IP blocklist/allowlist
export const ipList = pgTable(
  "ip_list",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    ip: varchar("ip", { length: 45 }).notNull(),
    cidr: integer("cidr"),
    type: text("type").notNull(), // "allow" or "block"
    reason: text("reason"),
    source: text("source").default("manual"), // manual, automatic, api
    expiresAt: timestamp("expires_at"),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    createdBy: uuid("created_by").references(() => user.id, { onDelete: "set null" }),
  },
  (table) => [
    index("ip_list_organization_id_idx").on(table.organizationId),
    index("ip_list_ip_idx").on(table.ip),
    index("ip_list_type_idx").on(table.type),
  ]
).enableRLS();

// IP scores (global reputation)
export const ipScore = pgTable(
  "ip_score",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    ip: varchar("ip", { length: 45 }).notNull().unique(),
    score: integer("score").notNull().default(100), // 0-100, higher is better
    totalRequests: bigint("total_requests", { mode: "number" }).default(0),
    blockedRequests: bigint("blocked_requests", { mode: "number" }).default(0),
    successfulRequests: bigint("successful_requests", { mode: "number" }).default(0),
    lastSeen: timestamp("last_seen").notNull().defaultNow(),
    firstSeen: timestamp("first_seen").notNull().defaultNow(),
    // Reputation factors
    country: text("country"),
    asn: integer("asn"),
    asnName: text("asn_name"),
    isProxy: boolean("is_proxy").default(false),
    isVpn: boolean("is_vpn").default(false),
    isTor: boolean("is_tor").default(false),
    isDatacenter: boolean("is_datacenter").default(false),
    // Attack history
    attackTypes: jsonb("attack_types").$type<string[]>(),
    lastAttack: timestamp("last_attack"),
    // Metadata
    metadata: jsonb("metadata"),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => [
    index("ip_score_ip_idx").on(table.ip),
    index("ip_score_score_idx").on(table.score),
  ]
).enableRLS();

// Connection attempts (for IP lookup in dashboard)
export const connectionAttempt = pgTable(
  "connection_attempt",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    backendId: uuid("backend_id")
      .references(() => backend.id, { onDelete: "set null" }),
    sourceIp: varchar("source_ip", { length: 45 }).notNull(),
    destPort: integer("dest_port"),
    protocol: protocolEnum("protocol"),
    success: boolean("success").notNull(),
    blockedReason: text("blocked_reason"),
    filterId: uuid("filter_id")
      .references(() => filter.id, { onDelete: "set null" }),
    latencyMs: integer("latency_ms"),
    bytesIn: bigint("bytes_in", { mode: "number" }),
    bytesOut: bigint("bytes_out", { mode: "number" }),
    metadata: jsonb("metadata"),
    timestamp: timestamp("timestamp").notNull().defaultNow(),
  },
  (table) => [
    index("connection_attempt_organization_id_idx").on(table.organizationId),
    index("connection_attempt_source_ip_idx").on(table.sourceIp),
    index("connection_attempt_timestamp_idx").on(table.timestamp),
  ]
).enableRLS();

// Attack events
export const attackEvent = pgTable(
  "attack_event",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    backendId: uuid("backend_id")
      .references(() => backend.id, { onDelete: "set null" }),
    type: text("type").notNull(), // syn_flood, udp_flood, http_flood, etc.
    severity: severityEnum("severity").notNull(),
    sourceIps: jsonb("source_ips").$type<string[]>(),
    sourcePorts: jsonb("source_ports").$type<number[]>(),
    destPorts: jsonb("dest_ports").$type<number[]>(),
    packetsPerSecond: bigint("packets_per_second", { mode: "number" }),
    bytesPerSecond: bigint("bytes_per_second", { mode: "number" }),
    totalPackets: bigint("total_packets", { mode: "number" }),
    totalBytes: bigint("total_bytes", { mode: "number" }),
    mitigationAction: filterActionEnum("mitigation_action"),
    mitigatedAt: timestamp("mitigated_at"),
    resolvedAt: timestamp("resolved_at"),
    metadata: jsonb("metadata"),
    startedAt: timestamp("started_at").notNull().defaultNow(),
    endedAt: timestamp("ended_at"),
  },
  (table) => [
    index("attack_event_organization_id_idx").on(table.organizationId),
    index("attack_event_backend_id_idx").on(table.backendId),
    index("attack_event_type_idx").on(table.type),
    index("attack_event_started_at_idx").on(table.startedAt),
  ]
).enableRLS();

// Traffic metrics (aggregated)
export const trafficMetric = pgTable(
  "traffic_metric",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    backendId: uuid("backend_id")
      .references(() => backend.id, { onDelete: "set null" }),
    timestamp: timestamp("timestamp").notNull(),
    intervalSeconds: integer("interval_seconds").notNull().default(60),
    requestsTotal: bigint("requests_total", { mode: "number" }).default(0),
    requestsAllowed: bigint("requests_allowed", { mode: "number" }).default(0),
    requestsBlocked: bigint("requests_blocked", { mode: "number" }).default(0),
    requestsChallenged: bigint("requests_challenged", { mode: "number" }).default(0),
    bytesIn: bigint("bytes_in", { mode: "number" }).default(0),
    bytesOut: bigint("bytes_out", { mode: "number" }).default(0),
    avgLatencyMs: real("avg_latency_ms"),
    p50LatencyMs: real("p50_latency_ms"),
    p95LatencyMs: real("p95_latency_ms"),
    p99LatencyMs: real("p99_latency_ms"),
    uniqueIps: integer("unique_ips"),
    errorCount: integer("error_count").default(0),
  },
  (table) => [
    index("traffic_metric_organization_id_idx").on(table.organizationId),
    index("traffic_metric_backend_id_idx").on(table.backendId),
    index("traffic_metric_timestamp_idx").on(table.timestamp),
  ]
).enableRLS();

// Audit log
export const auditLog = pgTable(
  "audit_log",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .references(() => organization.id, { onDelete: "set null" }),
    userId: uuid("user_id")
      .references(() => user.id, { onDelete: "set null" }),
    action: text("action").notNull(),
    resource: text("resource").notNull(),
    resourceId: text("resource_id"),
    oldValue: jsonb("old_value"),
    newValue: jsonb("new_value"),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    timestamp: timestamp("timestamp").notNull().defaultNow(),
  },
  (table) => [
    index("audit_log_organization_id_idx").on(table.organizationId),
    index("audit_log_user_id_idx").on(table.userId),
    index("audit_log_timestamp_idx").on(table.timestamp),
  ]
).enableRLS();

// GeoDNS configuration
export const geoDnsConfig = pgTable(
  "geo_dns_config",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    backendId: uuid("backend_id")
      .notNull()
      .references(() => backend.id, { onDelete: "cascade" }),
    enabled: boolean("enabled").default(false),
    defaultRegion: text("default_region"),
    regions: jsonb("regions").$type<{
      region: string;
      originIds: string[];
      weight: number;
    }[]>(),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => [
    index("geo_dns_config_backend_id_idx").on(table.backendId),
  ]
).enableRLS();

// Minecraft-specific settings
export const minecraftConfig = pgTable(
  "minecraft_config",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    backendId: uuid("backend_id")
      .notNull()
      .references(() => backend.id, { onDelete: "cascade" }),
    edition: text("edition").notNull(), // java, bedrock
    // Java Edition specific
    onlineModeCheck: boolean("online_mode_check").default(false),
    statusPingProtection: boolean("status_ping_protection").default(true),
    statusPingRateLimit: integer("status_ping_rate_limit").default(10),
    handshakeValidation: boolean("handshake_validation").default(true),
    maxPlayersPerIp: integer("max_players_per_ip").default(5),
    // Bedrock Edition specific (RakNet)
    raknetValidation: boolean("raknet_validation").default(true),
    raknetAmplificationProtection: boolean("raknet_amplification_protection").default(true),
    // Fallback server (when backend is offline)
    fallbackEnabled: boolean("fallback_enabled").default(false),
    fallbackMotd: text("fallback_motd"),
    fallbackVersion: text("fallback_version"),
    fallbackMaxPlayers: integer("fallback_max_players"),
    fallbackIconBase64: text("fallback_icon_base64"),
    // Timestamps
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => [
    index("minecraft_config_backend_id_idx").on(table.backendId),
  ]
).enableRLS();

// Relations
export const protectionOrganizationRelations = relations(
  protectionOrganization,
  ({ one }) => ({
    organization: one(organization, {
      fields: [protectionOrganization.organizationId],
      references: [organization.id],
    }),
  })
);

export const backendRelations = relations(backend, ({ one, many }) => ({
  organization: one(organization, {
    fields: [backend.organizationId],
    references: [organization.id],
  }),
  origins: many(backendOrigin),
  domains: many(backendDomain),
  filters: many(filter),
  attackEvents: many(attackEvent),
  trafficMetrics: many(trafficMetric),
  geoDnsConfig: one(geoDnsConfig),
  minecraftConfig: one(minecraftConfig),
}));

export const backendOriginRelations = relations(backendOrigin, ({ one }) => ({
  backend: one(backend, {
    fields: [backendOrigin.backendId],
    references: [backend.id],
  }),
}));

export const backendDomainRelations = relations(backendDomain, ({ one }) => ({
  backend: one(backend, {
    fields: [backendDomain.backendId],
    references: [backend.id],
  }),
}));

export const filterRelations = relations(filter, ({ one }) => ({
  organization: one(organization, {
    fields: [filter.organizationId],
    references: [organization.id],
  }),
  backend: one(backend, {
    fields: [filter.backendId],
    references: [backend.id],
  }),
}));

export const ipListRelations = relations(ipList, ({ one }) => ({
  organization: one(organization, {
    fields: [ipList.organizationId],
    references: [organization.id],
  }),
  createdByUser: one(user, {
    fields: [ipList.createdBy],
    references: [user.id],
  }),
}));

export const connectionAttemptRelations = relations(connectionAttempt, ({ one }) => ({
  organization: one(organization, {
    fields: [connectionAttempt.organizationId],
    references: [organization.id],
  }),
  backend: one(backend, {
    fields: [connectionAttempt.backendId],
    references: [backend.id],
  }),
  filter: one(filter, {
    fields: [connectionAttempt.filterId],
    references: [filter.id],
  }),
}));

export const attackEventRelations = relations(attackEvent, ({ one }) => ({
  organization: one(organization, {
    fields: [attackEvent.organizationId],
    references: [organization.id],
  }),
  backend: one(backend, {
    fields: [attackEvent.backendId],
    references: [backend.id],
  }),
}));

export const trafficMetricRelations = relations(trafficMetric, ({ one }) => ({
  organization: one(organization, {
    fields: [trafficMetric.organizationId],
    references: [organization.id],
  }),
  backend: one(backend, {
    fields: [trafficMetric.backendId],
    references: [backend.id],
  }),
}));

export const auditLogRelations = relations(auditLog, ({ one }) => ({
  organization: one(organization, {
    fields: [auditLog.organizationId],
    references: [organization.id],
  }),
  user: one(user, {
    fields: [auditLog.userId],
    references: [user.id],
  }),
}));

export const geoDnsConfigRelations = relations(geoDnsConfig, ({ one }) => ({
  backend: one(backend, {
    fields: [geoDnsConfig.backendId],
    references: [backend.id],
  }),
}));

export const minecraftConfigRelations = relations(minecraftConfig, ({ one }) => ({
  backend: one(backend, {
    fields: [minecraftConfig.backendId],
    references: [backend.id],
  }),
}));
