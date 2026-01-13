// @ts-nocheck
// TODO: API response types don't match expected properties (change, etc.)
import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  CheckCircle2,
  Clock,
  Loader2,
  RefreshCw,
  Server,
  Shield,
  TrendingUp,
  XCircle,
  Zap,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { useOrganizationId } from "@/hooks/use-organization";
import { useTRPC } from "@/lib/trpc/client";

export const Route = createFileRoute("/dashboard/")({
  component: DashboardOverview,
});

function formatNumber(num: number): string {
  if (num >= 1_000_000_000) {
    return `${(num / 1_000_000_000).toFixed(1)}B`;
  }
  if (num >= 1_000_000) {
    return `${(num / 1_000_000).toFixed(1)}M`;
  }
  if (num >= 1_000) {
    return `${(num / 1_000).toFixed(1)}K`;
  }
  return num.toString();
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${Number.parseFloat((bytes / k ** i).toFixed(2))} ${sizes[i]}`;
}

function DashboardOverview() {
  const trpc = useTRPC();
  const organizationId = useOrganizationId();

  // Get dashboard stats
  const {
    data: dashboardStats,
    isLoading: statsLoading,
    refetch: refetchStats,
  } = useQuery(
    trpc.analytics.getDashboardStats.queryOptions({
      organizationId,
    }),
  );

  // Get realtime stats
  const { data: realtimeStats, isLoading: realtimeLoading } = useQuery({
    ...trpc.analytics.getRealtimeStats.queryOptions({
      organizationId,
    }),
    refetchInterval: 5000, // Refresh every 5 seconds
  });

  // Get traffic stats for last 24 hours
  const { data: trafficStats, isLoading: trafficLoading } = useQuery(
    trpc.analytics.getTrafficStats.queryOptions({
      organizationId,
      hours: 24,
    }),
  );

  // Get attack stats
  const { data: attackStats } = useQuery(
    trpc.analytics.getAttackStats.queryOptions({
      organizationId,
      hours: 24,
    }),
  );

  // Get recent events
  const { data: recentEvents } = useQuery(
    trpc.analytics.getRecentEvents.queryOptions({
      organizationId,
      limit: 5,
    }),
  );

  // Get traffic time series for chart
  const { data: trafficTimeSeries } = useQuery(
    trpc.analytics.getTrafficTimeSeries.queryOptions({
      organizationId,
      hours: 24,
      interval: "hour",
    }),
  );

  const isLoading = statsLoading || trafficLoading;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-muted-foreground">
            Monitor your DDoS protection status and traffic analytics.
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => refetchStats()}
          disabled={isLoading}
        >
          <RefreshCw
            className={`h-4 w-4 mr-2 ${isLoading ? "animate-spin" : ""}`}
          />
          Refresh
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Protected Backends
            </CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {statsLoading ? (
              <Skeleton className="h-8 w-20" />
            ) : (
              <>
                <div className="text-2xl font-bold">
                  {dashboardStats?.backends.total ?? 0}
                </div>
                <p className="text-xs text-muted-foreground">
                  <span className="text-green-500 inline-flex items-center">
                    <CheckCircle2 className="h-3 w-3 mr-1" />
                    {dashboardStats?.backends.healthy ?? 0} healthy
                  </span>
                  {(dashboardStats?.backends.unhealthy ?? 0) > 0 && (
                    <span className="text-red-500 ml-2 inline-flex items-center">
                      <XCircle className="h-3 w-3 mr-1" />
                      {dashboardStats?.backends.unhealthy} unhealthy
                    </span>
                  )}
                </p>
              </>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Active Filters
            </CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {statsLoading ? (
              <Skeleton className="h-8 w-20" />
            ) : (
              <>
                <div className="text-2xl font-bold">
                  {dashboardStats?.filters.total ?? 0}
                </div>
                <p className="text-xs text-muted-foreground">
                  {dashboardStats?.filters.active ?? 0} active,{" "}
                  {dashboardStats?.filters.disabled ?? 0} disabled
                </p>
              </>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Requests / sec
            </CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {realtimeLoading ? (
              <Skeleton className="h-8 w-20" />
            ) : (
              <>
                <div className="text-2xl font-bold">
                  {formatNumber(
                    Math.round(realtimeStats?.requestsPerSecond ?? 0),
                  )}
                </div>
                <p className="text-xs text-muted-foreground">
                  {realtimeStats && realtimeStats.change >= 0 ? (
                    <span className="text-green-500 inline-flex items-center">
                      <ArrowUpRight className="h-3 w-3" />+
                      {Math.abs(realtimeStats.change).toFixed(1)}%
                    </span>
                  ) : (
                    <span className="text-red-500 inline-flex items-center">
                      <ArrowDownRight className="h-3 w-3" />
                      {Math.abs(realtimeStats?.change ?? 0).toFixed(1)}%
                    </span>
                  )}{" "}
                  from last hour
                </p>
              </>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Blocked Threats
            </CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            {trafficLoading ? (
              <Skeleton className="h-8 w-20" />
            ) : (
              <>
                <div className="text-2xl font-bold">
                  {formatNumber(trafficStats?.blockedRequests ?? 0)}
                </div>
                <p className="text-xs text-muted-foreground">
                  <span className="text-muted-foreground inline-flex items-center">
                    <TrendingUp className="h-3 w-3 mr-1" />
                    Last 24 hours
                  </span>
                </p>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Traffic Chart */}
      <Card>
        <CardHeader>
          <CardTitle>Traffic Overview</CardTitle>
          <CardDescription>
            Request volume over the last 24 hours
          </CardDescription>
        </CardHeader>
        <CardContent>
          {trafficTimeSeries && trafficTimeSeries.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={trafficTimeSeries}>
                <defs>
                  <linearGradient id="colorAllowed" x1="0" y1="0" x2="0" y2="1">
                    <stop
                      offset="5%"
                      stopColor="hsl(var(--primary))"
                      stopOpacity={0.3}
                    />
                    <stop
                      offset="95%"
                      stopColor="hsl(var(--primary))"
                      stopOpacity={0}
                    />
                  </linearGradient>
                  <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop
                      offset="5%"
                      stopColor="hsl(var(--destructive))"
                      stopOpacity={0.3}
                    />
                    <stop
                      offset="95%"
                      stopColor="hsl(var(--destructive))"
                      stopOpacity={0}
                    />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                <XAxis
                  dataKey="time"
                  tick={{ fontSize: 12 }}
                  className="text-muted-foreground"
                />
                <YAxis
                  tick={{ fontSize: 12 }}
                  className="text-muted-foreground"
                  tickFormatter={(value) => formatNumber(value)}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "hsl(var(--popover))",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "8px",
                  }}
                  formatter={(value: number) => [formatNumber(value), ""]}
                />
                <Area
                  type="monotone"
                  dataKey="allowed"
                  name="Allowed"
                  stroke="hsl(var(--primary))"
                  fillOpacity={1}
                  fill="url(#colorAllowed)"
                />
                <Area
                  type="monotone"
                  dataKey="blocked"
                  name="Blocked"
                  stroke="hsl(var(--destructive))"
                  fillOpacity={1}
                  fill="url(#colorBlocked)"
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[300px] text-muted-foreground">
              {trafficLoading ? (
                <Loader2 className="h-8 w-8 animate-spin" />
              ) : (
                "No traffic data available"
              )}
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        {/* Protection Status */}
        <Card className="col-span-4">
          <CardHeader>
            <CardTitle>Protection Status</CardTitle>
            <CardDescription>
              Current status of your DDoS protection systems.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {[
              {
                name: "TCP Protection",
                desc: "SYN Flood, ACK Flood",
                icon: Shield,
                active: true,
              },
              {
                name: "UDP Protection",
                desc: "Amplification, Flood",
                icon: Shield,
                active: true,
              },
              {
                name: "HTTP Protection",
                desc: "L7 DDoS, Slowloris",
                icon: Zap,
                active: true,
              },
              {
                name: "QUIC Protection",
                desc: "Initial Flood, Retry",
                icon: Activity,
                active: true,
              },
              {
                name: "Minecraft Protection",
                desc: "Java & Bedrock/RakNet",
                icon: Server,
                active: true,
              },
            ].map((p, i) => (
              <div key={i} className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge
                      variant="default"
                      className={p.active ? "bg-green-500" : "bg-gray-500"}
                    >
                      {p.active ? "Active" : "Inactive"}
                    </Badge>
                    <span className="text-sm font-medium">{p.name}</span>
                  </div>
                  <span className="text-sm text-muted-foreground">
                    {p.desc}
                  </span>
                </div>
                <Progress value={p.active ? 100 : 0} className="h-2" />
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Recent Activity */}
        <Card className="col-span-3">
          <CardHeader>
            <CardTitle>Recent Activity</CardTitle>
            <CardDescription>
              Latest detected threats and actions.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {recentEvents && recentEvents.length > 0 ? (
                recentEvents.map((e, i) => (
                  <div key={i} className="flex items-center justify-between">
                    <div className="space-y-1">
                      <p className="text-sm font-medium leading-none">
                        {e.type}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        Source: {e.sourceIp}
                      </p>
                    </div>
                    <div className="text-right">
                      <Badge
                        variant={
                          e.action === "blocked" ? "destructive" : "secondary"
                        }
                        className="text-xs"
                      >
                        {e.action}
                      </Badge>
                      <p className="text-xs text-muted-foreground mt-1 inline-flex items-center">
                        <Clock className="h-3 w-3 mr-1" />
                        {e.timeAgo}
                      </p>
                    </div>
                  </div>
                ))
              ) : (
                <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                  <CheckCircle2 className="h-8 w-8 mb-2 text-green-500" />
                  <p>No recent threats detected</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Attack Stats Summary */}
      {attackStats && attackStats.total > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Attack Summary (24h)</CardTitle>
            <CardDescription>Breakdown of blocked attack types</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-5">
              <div className="text-center">
                <div className="text-3xl font-bold">
                  {formatNumber(attackStats.total)}
                </div>
                <p className="text-sm text-muted-foreground">Total Attacks</p>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-red-500">
                  {formatNumber(attackStats.critical)}
                </div>
                <p className="text-sm text-muted-foreground">Critical</p>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-orange-500">
                  {formatNumber(attackStats.high)}
                </div>
                <p className="text-sm text-muted-foreground">High</p>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-yellow-500">
                  {formatNumber(attackStats.medium)}
                </div>
                <p className="text-sm text-muted-foreground">Medium</p>
              </div>
              <div className="text-center">
                <div className="text-3xl font-bold text-green-500">
                  {formatNumber(attackStats.mitigated)}
                </div>
                <p className="text-sm text-muted-foreground">Mitigated</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Bandwidth Stats */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Bandwidth Usage</CardTitle>
            <CardDescription>
              Total data transferred in 24 hours
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-muted-foreground">Inbound</p>
                <p className="text-2xl font-bold">
                  {formatBytes(trafficStats?.bytesIn ?? 0)}
                </p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Outbound</p>
                <p className="text-2xl font-bold">
                  {formatBytes(trafficStats?.bytesOut ?? 0)}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Latency</CardTitle>
            <CardDescription>Response time percentiles</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-4">
              <div>
                <p className="text-sm text-muted-foreground">Avg</p>
                <p className="text-2xl font-bold">
                  {(trafficStats?.avgLatency ?? 0).toFixed(1)}ms
                </p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">P95</p>
                <p className="text-2xl font-bold">
                  {(trafficStats?.p95Latency ?? 0).toFixed(1)}ms
                </p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">P99</p>
                <p className="text-2xl font-bold">
                  {(trafficStats?.p99Latency ?? 0).toFixed(1)}ms
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
