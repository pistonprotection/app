import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Activity,
  Globe,
  Shield,
  TrendingUp,
  ArrowUpRight,
  ArrowDownRight,
  Zap,
  Server,
  Loader2,
  RefreshCw,
  AlertTriangle,
  Search,
} from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
} from "recharts";
import { useTRPC } from "@/lib/trpc/client";
import { useSession } from "@daveyplate/better-auth-ui";
import { useQuery } from "@tanstack/react-query";

export const Route = createFileRoute("/dashboard/analytics")({
  component: AnalyticsPage,
});

type TimeRange = "1h" | "24h" | "7d" | "30d";

const timeRangeToHours: Record<TimeRange, number> = {
  "1h": 1,
  "24h": 24,
  "7d": 168,
  "30d": 720,
};

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${Number.parseFloat((bytes / k ** i).toFixed(2))} ${sizes[i]}`;
}

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

function AnalyticsPage() {
  const { data: session } = useSession();
  const [timeRange, setTimeRange] = useState<TimeRange>("24h");
  const [ipLookup, setIpLookup] = useState("");

  const trpc = useTRPC();
  const organizationId = session?.user?.id ?? "";

  // Get traffic stats
  const {
    data: trafficStats,
    isLoading: statsLoading,
    error: statsError,
    refetch: refetchStats,
  } = useQuery(
    trpc.analytics.getTrafficStats.queryOptions({
      organizationId,
      hours: timeRangeToHours[timeRange],
    })
  );

  // Get realtime stats
  const { data: realtimeStats } = useQuery(
    trpc.analytics.getRealtimeStats.queryOptions({
      organizationId,
    })
  );

  // Get attack stats
  const { data: attackStats, isLoading: attacksLoading } = useQuery(
    trpc.analytics.getAttackStats.queryOptions({
      organizationId,
      hours: timeRangeToHours[timeRange],
    })
  );

  // Get attack types
  const { data: attackTypes } = useQuery(
    trpc.analytics.getAttackTypes.queryOptions({
      organizationId,
      hours: timeRangeToHours[timeRange],
      limit: 10,
    })
  );

  // Get top source IPs
  const { data: topIps } = useQuery(
    trpc.analytics.getTopSourceIps.queryOptions({
      organizationId,
      hours: timeRangeToHours[timeRange],
      limit: 10,
      filter: "blocked",
    })
  );

  // Get geo distribution
  const { data: geoData } = useQuery(
    trpc.analytics.getGeoDistribution.queryOptions({
      organizationId,
      hours: timeRangeToHours[timeRange],
    })
  );

  // Get dashboard stats
  const { data: dashboardStats } = useQuery(
    trpc.analytics.getDashboardStats.queryOptions({
      organizationId,
    })
  );

  // IP lookup query
  const { data: ipScoreData, isLoading: ipLookupLoading } = useQuery({
    ...trpc.analytics.lookupIpScore.queryOptions({
      ip: ipLookup,
    }),
    enabled: ipLookup.length > 0,
  });

  if (statsError) {
    return (
      <div className="flex flex-col items-center justify-center h-64 space-y-4">
        <AlertTriangle className="h-12 w-12 text-destructive" />
        <p className="text-destructive">Failed to load analytics</p>
        <Button onClick={() => refetchStats()}>
          <RefreshCw className="mr-2 h-4 w-4" />
          Retry
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Analytics</h1>
          <p className="text-muted-foreground">
            Traffic analysis and threat intelligence.
          </p>
        </div>
        <Select
          value={timeRange}
          onValueChange={(v) => setTimeRange(v as TimeRange)}
        >
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="Select range" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="1h">Last Hour</SelectItem>
            <SelectItem value="24h">Last 24 Hours</SelectItem>
            <SelectItem value="7d">Last 7 Days</SelectItem>
            <SelectItem value="30d">Last 30 Days</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Requests</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {statsLoading ? (
                <Loader2 className="h-6 w-6 animate-spin" />
              ) : (
                formatNumber(trafficStats?.totalRequests ?? 0)
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              {realtimeStats && (
                <span className="text-green-500 inline-flex items-center">
                  <ArrowUpRight className="h-3 w-3" />
                  {Math.round(realtimeStats.requestsPerSecond)}/s
                </span>
              )}
              {" "}current rate
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Blocked Attacks</CardTitle>
            <Shield className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {statsLoading ? (
                <Loader2 className="h-6 w-6 animate-spin" />
              ) : (
                formatNumber(trafficStats?.blockedRequests ?? 0)
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              {attackStats && attackStats.ongoing > 0 ? (
                <span className="text-red-500 inline-flex items-center">
                  <AlertTriangle className="h-3 w-3 mr-1" />
                  {attackStats.ongoing} ongoing
                </span>
              ) : (
                <span className="text-green-500">No active attacks</span>
              )}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Bandwidth</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {statsLoading ? (
                <Loader2 className="h-6 w-6 animate-spin" />
              ) : (
                formatBytes(
                  (trafficStats?.bytesIn ?? 0) + (trafficStats?.bytesOut ?? 0)
                )
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              {realtimeStats && (
                <>
                  {formatBytes(realtimeStats.bytesPerSecond)}/s current
                </>
              )}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Backends</CardTitle>
            <Server className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {dashboardStats?.backends.healthy ?? 0}/
              {dashboardStats?.backends.total ?? 0}
            </div>
            <p className="text-xs text-muted-foreground">
              {(dashboardStats?.backends.degraded ?? 0) > 0 && (
                <span className="text-yellow-500 mr-2">
                  {dashboardStats?.backends.degraded} degraded
                </span>
              )}
              {(dashboardStats?.backends.unhealthy ?? 0) > 0 && (
                <span className="text-red-500">
                  {dashboardStats?.backends.unhealthy} unhealthy
                </span>
              )}
              {(dashboardStats?.backends.degraded ?? 0) === 0 &&
                (dashboardStats?.backends.unhealthy ?? 0) === 0 && (
                  <span className="text-green-500">All healthy</span>
                )}
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Charts Row */}
      <div className="grid gap-4 md:grid-cols-2">
        {/* Attack Types */}
        <Card>
          <CardHeader>
            <CardTitle>Attack Types</CardTitle>
            <CardDescription>
              Distribution of blocked attack vectors
            </CardDescription>
          </CardHeader>
          <CardContent>
            {attackTypes && attackTypes.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={attackTypes}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                  <XAxis
                    dataKey="type"
                    tick={{ fontSize: 12 }}
                    className="text-muted-foreground"
                  />
                  <YAxis className="text-muted-foreground" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(var(--popover))",
                      border: "1px solid hsl(var(--border))",
                      borderRadius: "8px",
                    }}
                  />
                  <Bar dataKey="count" fill="hsl(var(--destructive))" radius={4} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-[300px] text-muted-foreground">
                No attack data available
              </div>
            )}
          </CardContent>
        </Card>

        {/* Geographic Distribution */}
        <Card>
          <CardHeader>
            <CardTitle>Top Attack Sources</CardTitle>
            <CardDescription>Geographic distribution of blocked traffic</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {geoData && geoData.length > 0 ? (
                geoData.slice(0, 8).map((item, i) => (
                  <div key={i} className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Globe className="h-4 w-4 text-muted-foreground" />
                      <span className="font-medium">{item.country ?? "Unknown"}</span>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="w-32 h-2 bg-muted rounded overflow-hidden">
                        <div
                          className="h-2 bg-destructive rounded"
                          style={{
                            width: `${Math.min((item.count / (geoData[0]?.count || 1)) * 100, 100)}%`,
                          }}
                        />
                      </div>
                      <span className="text-sm text-muted-foreground w-16 text-right">
                        {formatNumber(item.count)}
                      </span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="flex items-center justify-center h-[200px] text-muted-foreground">
                  No geographic data available
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* IP Lookup */}
      <Card>
        <CardHeader>
          <CardTitle>IP Score Lookup</CardTitle>
          <CardDescription>
            Check the reputation score and details of any IP address
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4 mb-4">
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Enter IP address..."
                value={ipLookup}
                onChange={(e) => setIpLookup(e.target.value)}
                className="pl-9"
              />
            </div>
            {ipLookupLoading && <Loader2 className="h-5 w-5 animate-spin" />}
          </div>

          {ipScoreData && (
            <div className="grid gap-4 md:grid-cols-4">
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">Score</p>
                <p className="text-2xl font-bold">
                  {ipScoreData.score}
                  <span className="text-sm text-muted-foreground">/100</span>
                </p>
              </div>
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">Country</p>
                <p className="text-lg font-medium">{ipScoreData.country ?? "Unknown"}</p>
              </div>
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">ASN</p>
                <p className="text-lg font-medium">{ipScoreData.asn ?? "Unknown"}</p>
              </div>
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">Flags</p>
                <div className="flex gap-2 flex-wrap">
                  {ipScoreData.isProxy && (
                    <Badge variant="destructive">Proxy</Badge>
                  )}
                  {ipScoreData.isVpn && <Badge variant="destructive">VPN</Badge>}
                  {ipScoreData.isTor && <Badge variant="destructive">Tor</Badge>}
                  {ipScoreData.isDatacenter && (
                    <Badge variant="secondary">Datacenter</Badge>
                  )}
                  {!ipScoreData.isProxy &&
                    !ipScoreData.isVpn &&
                    !ipScoreData.isTor &&
                    !ipScoreData.isDatacenter && (
                      <Badge variant="outline">Clean</Badge>
                    )}
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Top Blocked IPs */}
      <Card>
        <CardHeader>
          <CardTitle>Top Blocked IPs</CardTitle>
          <CardDescription>
            Most frequently blocked source addresses
          </CardDescription>
        </CardHeader>
        <CardContent>
          {topIps && topIps.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IP Address</TableHead>
                  <TableHead className="text-right">Total</TableHead>
                  <TableHead className="text-right">Blocked</TableHead>
                  <TableHead className="text-right">Allowed</TableHead>
                  <TableHead className="text-right">Bandwidth</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {topIps.map((ip, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-mono">
                      <Button
                        variant="link"
                        className="p-0 h-auto font-mono"
                        onClick={() => setIpLookup(ip.sourceIp)}
                      >
                        {ip.sourceIp}
                      </Button>
                    </TableCell>
                    <TableCell className="text-right">
                      {formatNumber(ip.count)}
                    </TableCell>
                    <TableCell className="text-right text-destructive">
                      {formatNumber(ip.blockedCount)}
                    </TableCell>
                    <TableCell className="text-right text-green-500">
                      {formatNumber(ip.successfulCount)}
                    </TableCell>
                    <TableCell className="text-right">
                      {formatBytes(ip.bytesTotal)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="flex items-center justify-center py-8 text-muted-foreground">
              No blocked IP data available
            </div>
          )}
        </CardContent>
      </Card>

      {/* Attack Severity Distribution */}
      {attackStats && (
        <Card>
          <CardHeader>
            <CardTitle>Attack Severity Distribution</CardTitle>
            <CardDescription>
              Breakdown of attacks by severity level
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between mb-2">
                    <Zap className="h-4 w-4 text-muted-foreground" />
                    <Badge variant="outline">{attackStats.total}</Badge>
                  </div>
                  <div className="text-2xl font-bold">{attackStats.total}</div>
                  <p className="text-xs text-muted-foreground">Total Attacks</p>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between mb-2">
                    <AlertTriangle className="h-4 w-4 text-red-500" />
                    <Badge variant="destructive">{attackStats.critical}</Badge>
                  </div>
                  <div className="text-2xl font-bold">{attackStats.critical}</div>
                  <p className="text-xs text-muted-foreground">Critical</p>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between mb-2">
                    <AlertTriangle className="h-4 w-4 text-orange-500" />
                    <Badge className="bg-orange-500">{attackStats.high}</Badge>
                  </div>
                  <div className="text-2xl font-bold">{attackStats.high}</div>
                  <p className="text-xs text-muted-foreground">High</p>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between mb-2">
                    <AlertTriangle className="h-4 w-4 text-yellow-500" />
                    <Badge className="bg-yellow-500">{attackStats.medium}</Badge>
                  </div>
                  <div className="text-2xl font-bold">{attackStats.medium}</div>
                  <p className="text-xs text-muted-foreground">Medium</p>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between mb-2">
                    <Shield className="h-4 w-4 text-green-500" />
                    <Badge className="bg-green-500">{attackStats.mitigated}</Badge>
                  </div>
                  <div className="text-2xl font-bold">{attackStats.mitigated}</div>
                  <p className="text-xs text-muted-foreground">Mitigated</p>
                </CardContent>
              </Card>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
