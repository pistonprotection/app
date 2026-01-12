import { QueryClient, queryOptions } from "@tanstack/react-query";

const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8080";

// Types
export interface Backend {
  id: string;
  name: string;
  address: string;
  protocol: string;
  status: "healthy" | "degraded" | "offline";
  enabled: boolean;
  stats: {
    requests: number;
    blocked: number;
    latency: number;
  };
  createdAt: string;
  updatedAt: string;
}

export interface FilterRule {
  id: string;
  name: string;
  type: string;
  action: "drop" | "ratelimit" | "allow" | "log";
  priority: number;
  enabled: boolean;
  config: Record<string, unknown>;
  matches: number;
  createdAt: string;
  updatedAt: string;
}

export interface Metrics {
  totalRequests: number;
  blockedRequests: number;
  passedRequests: number;
  bytesIn: number;
  bytesOut: number;
  avgLatency: number;
  activeConnections: number;
  timestamp: string;
}

export interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  organizationId: string;
  createdAt: string;
}

// API Client
class ApiClient {
  private baseUrl: string;
  private token: string | null = null;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  setToken(token: string | null) {
    this.token = token;
  }

  private async fetch<T>(
    path: string,
    options: RequestInit = {}
  ): Promise<T> {
    const headers: HeadersInit = {
      "Content-Type": "application/json",
      ...options.headers,
    };

    if (this.token) {
      (headers as Record<string, string>)["Authorization"] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: "Unknown error" }));
      throw new Error(error.message || `HTTP ${response.status}`);
    }

    return response.json();
  }

  // Backends
  async listBackends(): Promise<Backend[]> {
    return this.fetch<Backend[]>("/api/v1/backends");
  }

  async getBackend(id: string): Promise<Backend> {
    return this.fetch<Backend>(`/api/v1/backends/${id}`);
  }

  async createBackend(data: Partial<Backend>): Promise<Backend> {
    return this.fetch<Backend>("/api/v1/backends", {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  async updateBackend(id: string, data: Partial<Backend>): Promise<Backend> {
    return this.fetch<Backend>(`/api/v1/backends/${id}`, {
      method: "PUT",
      body: JSON.stringify(data),
    });
  }

  async deleteBackend(id: string): Promise<void> {
    await this.fetch<void>(`/api/v1/backends/${id}`, {
      method: "DELETE",
    });
  }

  // Filter Rules
  async listFilterRules(): Promise<FilterRule[]> {
    return this.fetch<FilterRule[]>("/api/v1/filters");
  }

  async getFilterRule(id: string): Promise<FilterRule> {
    return this.fetch<FilterRule>(`/api/v1/filters/${id}`);
  }

  async createFilterRule(data: Partial<FilterRule>): Promise<FilterRule> {
    return this.fetch<FilterRule>("/api/v1/filters", {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  async updateFilterRule(id: string, data: Partial<FilterRule>): Promise<FilterRule> {
    return this.fetch<FilterRule>(`/api/v1/filters/${id}`, {
      method: "PUT",
      body: JSON.stringify(data),
    });
  }

  async deleteFilterRule(id: string): Promise<void> {
    await this.fetch<void>(`/api/v1/filters/${id}`, {
      method: "DELETE",
    });
  }

  // Metrics
  async getMetrics(backendId?: string): Promise<Metrics> {
    const path = backendId
      ? `/api/v1/metrics?backendId=${backendId}`
      : "/api/v1/metrics";
    return this.fetch<Metrics>(path);
  }

  async getMetricsHistory(
    backendId?: string,
    from?: string,
    to?: string
  ): Promise<Metrics[]> {
    const params = new URLSearchParams();
    if (backendId) params.append("backendId", backendId);
    if (from) params.append("from", from);
    if (to) params.append("to", to);
    return this.fetch<Metrics[]>(`/api/v1/metrics/history?${params}`);
  }

  // User
  async getCurrentUser(): Promise<User> {
    return this.fetch<User>("/api/v1/user/me");
  }
}

export const apiClient = new ApiClient(API_BASE_URL);

// React Query Options
export const backendsQueryOptions = () =>
  queryOptions({
    queryKey: ["backends"],
    queryFn: () => apiClient.listBackends(),
  });

export const backendQueryOptions = (id: string) =>
  queryOptions({
    queryKey: ["backends", id],
    queryFn: () => apiClient.getBackend(id),
  });

export const filterRulesQueryOptions = () =>
  queryOptions({
    queryKey: ["filterRules"],
    queryFn: () => apiClient.listFilterRules(),
  });

export const filterRuleQueryOptions = (id: string) =>
  queryOptions({
    queryKey: ["filterRules", id],
    queryFn: () => apiClient.getFilterRule(id),
  });

export const metricsQueryOptions = (backendId?: string) =>
  queryOptions({
    queryKey: ["metrics", backendId],
    queryFn: () => apiClient.getMetrics(backendId),
    refetchInterval: 5000, // Refresh every 5 seconds
  });

export const metricsHistoryQueryOptions = (
  backendId?: string,
  from?: string,
  to?: string
) =>
  queryOptions({
    queryKey: ["metricsHistory", backendId, from, to],
    queryFn: () => apiClient.getMetricsHistory(backendId, from, to),
  });

export const userQueryOptions = () =>
  queryOptions({
    queryKey: ["user"],
    queryFn: () => apiClient.getCurrentUser(),
  });
