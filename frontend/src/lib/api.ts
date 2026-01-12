import { queryOptions, useMutation, useQueryClient } from "@tanstack/react-query";

// Types
export interface Backend {
  id: string;
  name: string;
  host: string;
  port: number;
  protocol: "http" | "https";
  healthCheckPath: string;
  healthCheckInterval: number;
  weight: number;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface FilterRule {
  id: string;
  name: string;
  description: string;
  type: "rate_limit" | "ip_block" | "geo_block" | "header_filter" | "path_filter" | "custom";
  action: "block" | "allow" | "challenge" | "log";
  priority: number;
  isEnabled: boolean;
  conditions: FilterCondition[];
  rateLimit?: RateLimit;
  createdAt: string;
  updatedAt: string;
}

export interface FilterCondition {
  field: string;
  operator: "equals" | "contains" | "regex" | "gt" | "lt" | "in";
  value: string | number | string[];
}

export interface RateLimit {
  requests: number;
  window: number; // seconds
  burstSize?: number;
}

export interface Metrics {
  totalRequests: number;
  blockedRequests: number;
  allowedRequests: number;
  challengedRequests: number;
  avgResponseTime: number;
  bandwidthIn: number;
  bandwidthOut: number;
  activeConnections: number;
  requestsPerSecond: number;
  topAttackTypes: AttackType[];
  trafficByCountry: CountryTraffic[];
  requestsOverTime: TimeSeriesData[];
  responseTimeOverTime: TimeSeriesData[];
}

export interface AttackType {
  type: string;
  count: number;
  percentage: number;
}

export interface CountryTraffic {
  country: string;
  countryCode: string;
  requests: number;
  blocked: number;
}

export interface TimeSeriesData {
  timestamp: string;
  value: number;
  blocked?: number;
  allowed?: number;
}

export interface Subscription {
  id: string;
  plan: "free" | "starter" | "professional" | "enterprise";
  status: "active" | "canceled" | "past_due" | "trialing";
  currentPeriodStart: string;
  currentPeriodEnd: string;
  cancelAtPeriodEnd: boolean;
  usage: SubscriptionUsage;
}

export interface SubscriptionUsage {
  requests: number;
  requestsLimit: number;
  bandwidth: number;
  bandwidthLimit: number;
  backends: number;
  backendsLimit: number;
  rules: number;
  rulesLimit: number;
}

export interface Plan {
  id: string;
  name: string;
  price: number;
  interval: "monthly" | "yearly";
  features: string[];
  limits: {
    requests: number;
    bandwidth: number;
    backends: number;
    rules: number;
  };
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  lastUsed: string | null;
  createdAt: string;
  expiresAt: string | null;
  scopes: string[];
}

export interface User {
  id: string;
  email: string;
  name: string;
  avatar?: string;
  role: "owner" | "admin" | "member";
  createdAt: string;
}

// API Base URL
const API_BASE_URL = import.meta.env.VITE_API_URL || "/api";

// Generic fetch wrapper
async function apiFetch<T>(
  endpoint: string,
  options?: RequestInit
): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
    credentials: "include",
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || `API Error: ${response.status}`);
  }

  return response.json();
}

// Backend API
export const backendsQueryOptions = () =>
  queryOptions({
    queryKey: ["backends"],
    queryFn: () => apiFetch<Backend[]>("/backends"),
  });

export const backendQueryOptions = (id: string) =>
  queryOptions({
    queryKey: ["backends", id],
    queryFn: () => apiFetch<Backend>(`/backends/${id}`),
  });

export function useCreateBackend() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: Omit<Backend, "id" | "createdAt" | "updatedAt">) =>
      apiFetch<Backend>("/backends", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["backends"] });
    },
  });
}

export function useUpdateBackend() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...data }: Partial<Backend> & { id: string }) =>
      apiFetch<Backend>(`/backends/${id}`, {
        method: "PATCH",
        body: JSON.stringify(data),
      }),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ["backends"] });
      queryClient.invalidateQueries({ queryKey: ["backends", variables.id] });
    },
  });
}

export function useDeleteBackend() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<void>(`/backends/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["backends"] });
    },
  });
}

// Filter Rules API
export const filterRulesQueryOptions = () =>
  queryOptions({
    queryKey: ["filter-rules"],
    queryFn: () => apiFetch<FilterRule[]>("/filter-rules"),
  });

export const filterRuleQueryOptions = (id: string) =>
  queryOptions({
    queryKey: ["filter-rules", id],
    queryFn: () => apiFetch<FilterRule>(`/filter-rules/${id}`),
  });

export function useCreateFilterRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: Omit<FilterRule, "id" | "createdAt" | "updatedAt">) =>
      apiFetch<FilterRule>("/filter-rules", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["filter-rules"] });
    },
  });
}

export function useUpdateFilterRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...data }: Partial<FilterRule> & { id: string }) =>
      apiFetch<FilterRule>(`/filter-rules/${id}`, {
        method: "PATCH",
        body: JSON.stringify(data),
      }),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ["filter-rules"] });
      queryClient.invalidateQueries({ queryKey: ["filter-rules", variables.id] });
    },
  });
}

export function useDeleteFilterRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<void>(`/filter-rules/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["filter-rules"] });
    },
  });
}

// Metrics API
export const metricsQueryOptions = (timeRange: string = "24h") =>
  queryOptions({
    queryKey: ["metrics", timeRange],
    queryFn: () => apiFetch<Metrics>(`/metrics?range=${timeRange}`),
    refetchInterval: 30000, // Refetch every 30 seconds
  });

export const realtimeMetricsQueryOptions = () =>
  queryOptions({
    queryKey: ["metrics", "realtime"],
    queryFn: () => apiFetch<Metrics>("/metrics/realtime"),
    refetchInterval: 5000, // Refetch every 5 seconds
  });

// Subscription/Billing API
export const subscriptionQueryOptions = () =>
  queryOptions({
    queryKey: ["subscription"],
    queryFn: () => apiFetch<Subscription>("/subscription"),
  });

export const plansQueryOptions = () =>
  queryOptions({
    queryKey: ["plans"],
    queryFn: () => apiFetch<Plan[]>("/plans"),
  });

export function useUpgradeSubscription() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (planId: string) =>
      apiFetch<Subscription>("/subscription/upgrade", {
        method: "POST",
        body: JSON.stringify({ planId }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["subscription"] });
    },
  });
}

export function useCancelSubscription() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () =>
      apiFetch<Subscription>("/subscription/cancel", {
        method: "POST",
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["subscription"] });
    },
  });
}

// API Keys
export const apiKeysQueryOptions = () =>
  queryOptions({
    queryKey: ["api-keys"],
    queryFn: () => apiFetch<ApiKey[]>("/api-keys"),
  });

export function useCreateApiKey() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: { name: string; scopes: string[]; expiresAt?: string }) =>
      apiFetch<ApiKey & { key: string }>("/api-keys", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    },
  });
}

export function useDeleteApiKey() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<void>(`/api-keys/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    },
  });
}

// User/Profile API
export const userQueryOptions = () =>
  queryOptions({
    queryKey: ["user"],
    queryFn: () => apiFetch<User>("/user"),
  });

export function useUpdateUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: Partial<User>) =>
      apiFetch<User>("/user", {
        method: "PATCH",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["user"] });
    },
  });
}
