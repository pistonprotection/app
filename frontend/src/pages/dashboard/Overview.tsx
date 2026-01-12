import { useQuery } from "@tanstack/react-query";
import {
  Shield,
  Zap,
  Globe,
  TrendingUp,
  ArrowUpRight,
  ArrowDownRight,
  Activity,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { metricsQueryOptions, subscriptionQueryOptions } from "@/lib/api";
import { formatNumber, formatBytes } from "@/lib/utils";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from "recharts";

// Mock data for development
const mockMetrics = {
  totalRequests: 12847293,
  blockedRequests: 284739,
  allowedRequests: 12562554,
  challengedRequests: 45000,
  avgResponseTime: 45,
  bandwidthIn: 1024 * 1024 * 1024 * 2.5,
  bandwidthOut: 1024 * 1024 * 1024 * 8.2,
  activeConnections: 1247,
  requestsPerSecond: 4521,
  topAttackTypes: [
    { type: "DDoS", count: 150000, percentage: 52.7 },
    { type: "SQL Injection", count: 45000, percentage: 15.8 },
    { type: "XSS", count: 32000, percentage: 11.2 },
    { type: "Bot Traffic", count: 28000, percentage: 9.8 },
    { type: "Other", count: 29739, percentage: 10.5 },
  ],
  trafficByCountry: [
    { country: "United States", countryCode: "US", requests: 5000000, blocked: 50000 },
    { country: "Germany", countryCode: "DE", requests: 2000000, blocked: 20000 },
    { country: "Japan", countryCode: "JP", requests: 1500000, blocked: 15000 },
    { country: "United Kingdom", countryCode: "GB", requests: 1200000, blocked: 12000 },
    { country: "France", countryCode: "FR", requests: 800000, blocked: 8000 },
  ],
  requestsOverTime: Array.from({ length: 24 }, (_, i) => ({
    timestamp: `${i}:00`,
    value: Math.floor(Math.random() * 500000) + 300000,
    blocked: Math.floor(Math.random() * 20000) + 5000,
    allowed: Math.floor(Math.random() * 480000) + 295000,
  })),
  responseTimeOverTime: Array.from({ length: 24 }, (_, i) => ({
    timestamp: `${i}:00`,
    value: Math.floor(Math.random() * 30) + 30,
  })),
};

const mockSubscription = {
  id: "sub_123",
  plan: "professional" as const,
  status: "active" as const,
  currentPeriodStart: "2024-01-01",
  currentPeriodEnd: "2024-02-01",
  cancelAtPeriodEnd: false,
  usage: {
    requests: 12847293,
    requestsLimit: 50000000,
    bandwidth: 1024 * 1024 * 1024 * 10.7,
    bandwidthLimit: 1024 * 1024 * 1024 * 100,
    backends: 5,
    backendsLimit: 10,
    rules: 23,
    rulesLimit: 50,
  },
};

const COLORS = ["#8b5cf6", "#06b6d4", "#10b981", "#f59e0b", "#ef4444"];

export function Overview() {
  const { data: metrics, isLoading: metricsLoading } = useQuery({
    ...metricsQueryOptions("24h"),
    placeholderData: mockMetrics,
  });

  const { data: subscription, isLoading: subscriptionLoading } = useQuery({
    ...subscriptionQueryOptions(),
    placeholderData: mockSubscription,
  });

  const blockRate = metrics
    ? ((metrics.blockedRequests / metrics.totalRequests) * 100).toFixed(1)
    : "0";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground">
          Monitor your protection status and traffic analytics
        </p>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Requests</CardTitle>
            <Globe className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {metricsLoading ? (
              <Skeleton className="h-8 w-24" />
            ) : (
              <>
                <div className="text-2xl font-bold">
                  {formatNumber(metrics?.totalRequests || 0)}
                </div>
                <p className="text-xs text-muted-foreground flex items-center gap-1">
                  <ArrowUpRight className="h-3 w-3 text-green-500" />
                  <span className="text-green-500">+12.5%</span> from last period
                </p>
              </>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Threats Blocked</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {metricsLoading ? (
              <Skeleton className="h-8 w-24" />
            ) : (
              <>
                <div className="text-2xl font-bold">
                  {formatNumber(metrics?.blockedRequests || 0)}
                </div>
                <p className="text-xs text-muted-foreground flex items-center gap-1">
                  <span className="text-nova">{blockRate}%</span> block rate
                </p>
              </>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Avg Response Time</CardTitle>
            <Zap className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {metricsLoading ? (
              <Skeleton className="h-8 w-24" />
            ) : (
              <>
                <div className="text-2xl font-bold">
                  {metrics?.avgResponseTime || 0}ms
                </div>
                <p className="text-xs text-muted-foreground flex items-center gap-1">
                  <ArrowDownRight className="h-3 w-3 text-green-500" />
                  <span className="text-green-500">-5ms</span> from last period
                </p>
              </>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Requests/sec</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {metricsLoading ? (
              <Skeleton className="h-8 w-24" />
            ) : (
              <>
                <div className="text-2xl font-bold">
                  {formatNumber(metrics?.requestsPerSecond || 0)}
                </div>
                <p className="text-xs text-muted-foreground flex items-center gap-1">
                  <span className="text-muted-foreground">
                    {metrics?.activeConnections || 0} active connections
                  </span>
                </p>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Charts Row */}
      <div className="grid gap-4 md:grid-cols-7">
        {/* Traffic Chart */}
        <Card className="md:col-span-4">
          <CardHeader>
            <CardTitle>Traffic Overview</CardTitle>
            <CardDescription>
              Requests over the last 24 hours
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={metrics?.requestsOverTime || []}>
                  <defs>
                    <linearGradient id="colorAllowed" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis
                    dataKey="timestamp"
                    className="text-xs"
                    tick={{ fill: "hsl(var(--muted-foreground))" }}
                  />
                  <YAxis
                    className="text-xs"
                    tick={{ fill: "hsl(var(--muted-foreground))" }}
                    tickFormatter={(value) => formatNumber(value)}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "8px",
                    }}
                    labelStyle={{ color: "hsl(var(--foreground))" }}
                  />
                  <Area
                    type="monotone"
                    dataKey="allowed"
                    stroke="#8b5cf6"
                    fillOpacity={1}
                    fill="url(#colorAllowed)"
                    name="Allowed"
                  />
                  <Area
                    type="monotone"
                    dataKey="blocked"
                    stroke="#ef4444"
                    fillOpacity={1}
                    fill="url(#colorBlocked)"
                    name="Blocked"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Attack Types Chart */}
        <Card className="md:col-span-3">
          <CardHeader>
            <CardTitle>Threat Distribution</CardTitle>
            <CardDescription>Types of blocked threats</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="h-[200px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={(metrics?.topAttackTypes || []).map((item) => ({
                      name: item.type,
                      value: item.count,
                    }))}
                    cx="50%"
                    cy="50%"
                    innerRadius={40}
                    outerRadius={80}
                    fill="#8884d8"
                    paddingAngle={2}
                    dataKey="value"
                  >
                    {(metrics?.topAttackTypes || []).map((_, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={COLORS[index % COLORS.length]}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--card))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "8px",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-4 space-y-2">
              {(metrics?.topAttackTypes || []).map((attack, index) => (
                <div key={attack.type} className="flex items-center gap-2">
                  <div
                    className="h-3 w-3 rounded-full"
                    style={{ backgroundColor: COLORS[index % COLORS.length] }}
                  />
                  <span className="flex-1 text-sm">{attack.type}</span>
                  <span className="text-sm text-muted-foreground">
                    {attack.percentage}%
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Usage & Status Row */}
      <div className="grid gap-4 md:grid-cols-2">
        {/* Usage Card */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Plan Usage</CardTitle>
                <CardDescription>Current billing period</CardDescription>
              </div>
              <Badge variant="nova" className="capitalize">
                {subscription?.plan || "Free"}
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {subscriptionLoading ? (
              <div className="space-y-4">
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-full" />
              </div>
            ) : (
              <>
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span>Requests</span>
                    <span className="text-muted-foreground">
                      {formatNumber(subscription?.usage.requests || 0)} /{" "}
                      {formatNumber(subscription?.usage.requestsLimit || 0)}
                    </span>
                  </div>
                  <Progress
                    value={
                      ((subscription?.usage.requests || 0) /
                        (subscription?.usage.requestsLimit || 1)) *
                      100
                    }
                  />
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span>Bandwidth</span>
                    <span className="text-muted-foreground">
                      {formatBytes(subscription?.usage.bandwidth || 0)} /{" "}
                      {formatBytes(subscription?.usage.bandwidthLimit || 0)}
                    </span>
                  </div>
                  <Progress
                    value={
                      ((subscription?.usage.bandwidth || 0) /
                        (subscription?.usage.bandwidthLimit || 1)) *
                      100
                    }
                  />
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span>Backends</span>
                    <span className="text-muted-foreground">
                      {subscription?.usage.backends || 0} /{" "}
                      {subscription?.usage.backendsLimit || 0}
                    </span>
                  </div>
                  <Progress
                    value={
                      ((subscription?.usage.backends || 0) /
                        (subscription?.usage.backendsLimit || 1)) *
                      100
                    }
                  />
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span>Filter Rules</span>
                    <span className="text-muted-foreground">
                      {subscription?.usage.rules || 0} /{" "}
                      {subscription?.usage.rulesLimit || 0}
                    </span>
                  </div>
                  <Progress
                    value={
                      ((subscription?.usage.rules || 0) /
                        (subscription?.usage.rulesLimit || 1)) *
                      100
                    }
                  />
                </div>
              </>
            )}
          </CardContent>
        </Card>

        {/* Top Traffic Countries */}
        <Card>
          <CardHeader>
            <CardTitle>Top Traffic Sources</CardTitle>
            <CardDescription>By country</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {(metrics?.trafficByCountry || []).map((country) => (
                <div key={country.countryCode} className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2">
                      <span className="text-lg">
                        {getCountryFlag(country.countryCode)}
                      </span>
                      <span>{country.country}</span>
                    </div>
                    <div className="text-right">
                      <span className="font-medium">
                        {formatNumber(country.requests)}
                      </span>
                      <span className="ml-2 text-destructive text-xs">
                        ({formatNumber(country.blocked)} blocked)
                      </span>
                    </div>
                  </div>
                  <Progress
                    value={
                      (country.requests /
                        (metrics?.trafficByCountry[0]?.requests || 1)) *
                      100
                    }
                    className="h-1"
                  />
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Bandwidth In</p>
                <p className="text-xl font-bold">
                  {formatBytes(metrics?.bandwidthIn || 0)}
                </p>
              </div>
              <TrendingUp className="h-8 w-8 text-green-500 opacity-50" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Bandwidth Out</p>
                <p className="text-xl font-bold">
                  {formatBytes(metrics?.bandwidthOut || 0)}
                </p>
              </div>
              <TrendingUp className="h-8 w-8 text-blue-500 opacity-50" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Challenged</p>
                <p className="text-xl font-bold">
                  {formatNumber(metrics?.challengedRequests || 0)}
                </p>
              </div>
              <Shield className="h-8 w-8 text-yellow-500 opacity-50" />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Active Conns</p>
                <p className="text-xl font-bold">
                  {formatNumber(metrics?.activeConnections || 0)}
                </p>
              </div>
              <Activity className="h-8 w-8 text-nova opacity-50" />
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function getCountryFlag(countryCode: string): string {
  const codePoints = countryCode
    .toUpperCase()
    .split("")
    .map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}
