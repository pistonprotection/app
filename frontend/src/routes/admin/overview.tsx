import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  Globe,
  Server,
  TrendingUp,
  Users,
  Zap,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useTRPC } from "@/lib/trpc/client";

export const Route = createFileRoute("/admin/overview")({
  component: AdminOverview,
});

function AdminOverview() {
  const trpc = useTRPC();

  // Get platform stats
  const { data: platformStats } = useQuery(
    trpc.admin.getPlatformStats.queryOptions(),
  );

  // Get recent attacks
  const { data: recentAttacks } = useQuery(
    trpc.admin.getRecentAttacks.queryOptions({ limit: 5 }),
  );

  // Get system health
  const { data: systemHealth } = useQuery(
    trpc.admin.getSystemHealth.queryOptions(),
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Admin Overview</h1>
        <p className="text-muted-foreground">
          Platform-wide statistics and system health
        </p>
      </div>

      {/* Platform Stats */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Total Organizations
            </CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {platformStats?.totalOrganizations ?? 0}
            </div>
            <p className="text-xs text-muted-foreground">
              {platformStats?.activeOrganizations ?? 0} active
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Users</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {platformStats?.totalUsers ?? 0}
            </div>
            <p className="text-xs text-muted-foreground">
              {platformStats?.activeUsers ?? 0} active this week
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Total Backends
            </CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {platformStats?.totalBackends ?? 0}
            </div>
            <p className="text-xs text-muted-foreground">
              {platformStats?.healthyBackends ?? 0} healthy
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Attacks (24h)</CardTitle>
            <AlertTriangle className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {platformStats?.attacksLast24h ?? 0}
            </div>
            <p className="text-xs text-muted-foreground">
              {platformStats?.mitigatedAttacks ?? 0} mitigated
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Traffic Stats */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Requests (24h)
            </CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {formatNumber(platformStats?.requestsLast24h ?? 0)}
            </div>
            <p className="text-xs text-muted-foreground">
              {formatNumber(platformStats?.blockedRequestsLast24h ?? 0)} blocked
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Bandwidth (24h)
            </CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {formatBytes(platformStats?.bandwidthLast24h ?? 0)}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Unique IPs (24h)
            </CardTitle>
            <Globe className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {formatNumber(platformStats?.uniqueIpsLast24h ?? 0)}
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {/* System Health */}
        <Card>
          <CardHeader>
            <CardTitle>System Health</CardTitle>
            <CardDescription>
              Service status across the platform
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {systemHealth ? (
                <>
                  <ServiceStatus
                    name="Gateway"
                    status={systemHealth.gateway}
                    latency={systemHealth.gatewayLatency}
                  />
                  <ServiceStatus
                    name="Auth Service"
                    status={systemHealth.auth}
                    latency={systemHealth.authLatency}
                  />
                  <ServiceStatus
                    name="Config Manager"
                    status={systemHealth.configMgr}
                    latency={systemHealth.configMgrLatency}
                  />
                  <ServiceStatus
                    name="Metrics Service"
                    status={systemHealth.metrics}
                    latency={systemHealth.metricsLatency}
                  />
                  <ServiceStatus
                    name="Database"
                    status={systemHealth.database}
                    latency={systemHealth.databaseLatency}
                  />
                  <ServiceStatus
                    name="Redis"
                    status={systemHealth.redis}
                    latency={systemHealth.redisLatency}
                  />
                </>
              ) : (
                <p className="text-muted-foreground">
                  Loading system health...
                </p>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Recent Attacks */}
        <Card>
          <CardHeader>
            <CardTitle>Recent Attacks</CardTitle>
            <CardDescription>
              Latest detected attacks across the platform
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {recentAttacks && recentAttacks.length > 0 ? (
                recentAttacks.map((attack) => (
                  <div
                    key={attack.id}
                    className="flex items-center justify-between"
                  >
                    <div className="flex items-center gap-3">
                      <Zap className="h-4 w-4 text-destructive" />
                      <div>
                        <p className="font-medium">{attack.type}</p>
                        <p className="text-xs text-muted-foreground">
                          {attack.organizationName}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge
                        variant={
                          attack.severity === "critical"
                            ? "destructive"
                            : attack.severity === "high"
                              ? "destructive"
                              : "secondary"
                        }
                      >
                        {attack.severity}
                      </Badge>
                      <span className="text-xs text-muted-foreground">
                        {formatTimeAgo(attack.startedAt)}
                      </span>
                    </div>
                  </div>
                ))
              ) : (
                <p className="text-muted-foreground">No recent attacks</p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function ServiceStatus({
  name,
  status,
  latency,
}: {
  name: string;
  status: "healthy" | "degraded" | "unhealthy";
  latency?: number;
}) {
  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-2">
        <div
          className={`h-2 w-2 rounded-full ${
            status === "healthy"
              ? "bg-green-500"
              : status === "degraded"
                ? "bg-yellow-500"
                : "bg-red-500"
          }`}
        />
        <span className="font-medium">{name}</span>
      </div>
      {latency !== undefined && (
        <span className="text-sm text-muted-foreground">{latency}ms</span>
      )}
    </div>
  );
}

function formatNumber(num: number): string {
  if (num >= 1_000_000_000) return `${(num / 1_000_000_000).toFixed(1)}B`;
  if (num >= 1_000_000) return `${(num / 1_000_000).toFixed(1)}M`;
  if (num >= 1_000) return `${(num / 1_000).toFixed(1)}K`;
  return num.toString();
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${Number.parseFloat((bytes / k ** i).toFixed(2))} ${sizes[i]}`;
}

function formatTimeAgo(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - new Date(date).getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${diffDays}d ago`;
}
