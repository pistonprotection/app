import { createFileRoute } from "@tanstack/react-router";
import {
  Activity,
  ArrowUp,
  BarChart3,
  Clock,
  Cpu,
  Database,
  HardDrive,
  Network,
  RefreshCw,
  Server,
  TrendingUp,
  Wifi,
  Zap,
} from "lucide-react";
import { useState } from "react";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export const Route = createFileRoute("/admin/metrics")({
  component: AdminMetricsPage,
});

// Mock metrics data
const systemMetrics = {
  workers: {
    total: 12,
    healthy: 11,
    unhealthy: 1,
    avgCpu: 45,
    avgMemory: 62,
  },
  traffic: {
    currentRps: 125000,
    peakRps: 450000,
    avgLatency: 12,
    p99Latency: 45,
    totalRequests24h: 8500000000,
    totalBytes24h: 45000000000000,
  },
  ebpf: {
    packetsProcessed: 125000000000,
    packetsDropped: 850000000,
    xdpProgramsLoaded: 48,
    avgProcessingTime: 0.8, // microseconds
  },
  database: {
    connections: 45,
    maxConnections: 100,
    queryLatency: 2.5,
    cacheHitRate: 98.5,
  },
  redis: {
    connections: 24,
    memoryUsed: 2.1, // GB
    memoryMax: 8, // GB
    hitRate: 99.2,
    opsPerSec: 125000,
  },
};

const workerNodes = [
  {
    id: "worker-1",
    hostname: "xdp-worker-eu-1",
    region: "EU-West",
    status: "healthy",
    cpu: 42,
    memory: 58,
    networkIn: 4.5, // Gbps
    networkOut: 3.2,
    packetsPerSec: 12500000,
    uptime: "45d 12h",
  },
  {
    id: "worker-2",
    hostname: "xdp-worker-eu-2",
    region: "EU-West",
    status: "healthy",
    cpu: 38,
    memory: 52,
    networkIn: 3.8,
    networkOut: 2.9,
    packetsPerSec: 10800000,
    uptime: "45d 12h",
  },
  {
    id: "worker-3",
    hostname: "xdp-worker-us-1",
    region: "US-East",
    status: "healthy",
    cpu: 55,
    memory: 68,
    networkIn: 6.2,
    networkOut: 4.8,
    packetsPerSec: 18200000,
    uptime: "32d 8h",
  },
  {
    id: "worker-4",
    hostname: "xdp-worker-us-2",
    region: "US-East",
    status: "degraded",
    cpu: 85,
    memory: 82,
    networkIn: 8.1,
    networkOut: 6.5,
    packetsPerSec: 22000000,
    uptime: "32d 8h",
  },
  {
    id: "worker-5",
    hostname: "xdp-worker-asia-1",
    region: "Asia-Pacific",
    status: "healthy",
    cpu: 35,
    memory: 48,
    networkIn: 2.8,
    networkOut: 2.1,
    packetsPerSec: 8500000,
    uptime: "28d 4h",
  },
];

function AdminMetricsPage() {
  const [timeRange, setTimeRange] = useState("1h");
  const [autoRefresh, setAutoRefresh] = useState(true);

  const formatNumber = (num: number) => {
    if (num >= 1000000000) return `${(num / 1000000000).toFixed(1)}B`;
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
    return num.toString();
  };

  const formatBytes = (bytes: number) => {
    if (bytes >= 1000000000000)
      return `${(bytes / 1000000000000).toFixed(1)} TB`;
    if (bytes >= 1000000000) return `${(bytes / 1000000000).toFixed(1)} GB`;
    if (bytes >= 1000000) return `${(bytes / 1000000).toFixed(1)} MB`;
    return `${bytes} bytes`;
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">System Metrics</h1>
          <p className="text-muted-foreground">
            Real-time platform performance and health monitoring
          </p>
        </div>
        <div className="flex items-center gap-4">
          <Select value={timeRange} onValueChange={(value) => setTimeRange(value ?? "15m")}>
            <SelectTrigger className="w-[140px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="5m">Last 5 minutes</SelectItem>
              <SelectItem value="15m">Last 15 minutes</SelectItem>
              <SelectItem value="1h">Last hour</SelectItem>
              <SelectItem value="6h">Last 6 hours</SelectItem>
              <SelectItem value="24h">Last 24 hours</SelectItem>
              <SelectItem value="7d">Last 7 days</SelectItem>
            </SelectContent>
          </Select>
          <Button
            variant={autoRefresh ? "default" : "outline"}
            size="sm"
            onClick={() => setAutoRefresh(!autoRefresh)}
          >
            <RefreshCw
              className={`h-4 w-4 mr-2 ${autoRefresh ? "animate-spin" : ""}`}
            />
            {autoRefresh ? "Live" : "Paused"}
          </Button>
        </div>
      </div>

      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="workers">Workers</TabsTrigger>
          <TabsTrigger value="traffic">Traffic</TabsTrigger>
          <TabsTrigger value="infrastructure">Infrastructure</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6 mt-6">
          {/* Key Metrics */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">
                  Current RPS
                </CardTitle>
                <Activity className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {formatNumber(systemMetrics.traffic.currentRps)}
                </div>
                <div className="flex items-center text-xs text-green-600">
                  <ArrowUp className="h-3 w-3 mr-1" />
                  <span>12% from last hour</span>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">
                  Avg Latency
                </CardTitle>
                <Clock className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {systemMetrics.traffic.avgLatency}ms
                </div>
                <div className="text-xs text-muted-foreground">
                  p99: {systemMetrics.traffic.p99Latency}ms
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">
                  Worker Health
                </CardTitle>
                <Server className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {systemMetrics.workers.healthy}/{systemMetrics.workers.total}
                </div>
                <Progress
                  value={
                    (systemMetrics.workers.healthy /
                      systemMetrics.workers.total) *
                    100
                  }
                  className="mt-2"
                />
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Drop Rate</CardTitle>
                <Zap className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {(
                    (systemMetrics.ebpf.packetsDropped /
                      systemMetrics.ebpf.packetsProcessed) *
                    100
                  ).toFixed(2)}
                  %
                </div>
                <div className="text-xs text-muted-foreground">
                  {formatNumber(systemMetrics.ebpf.packetsDropped)} dropped
                </div>
              </CardContent>
            </Card>
          </div>

          {/* System Resources */}
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>eBPF/XDP Performance</CardTitle>
                <CardDescription>Packet processing statistics</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">
                    Packets Processed (24h)
                  </span>
                  <span className="font-mono font-medium">
                    {formatNumber(systemMetrics.ebpf.packetsProcessed)}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">
                    XDP Programs Loaded
                  </span>
                  <span className="font-mono font-medium">
                    {systemMetrics.ebpf.xdpProgramsLoaded}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">
                    Avg Processing Time
                  </span>
                  <span className="font-mono font-medium">
                    {systemMetrics.ebpf.avgProcessingTime}µs
                  </span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Database & Cache</CardTitle>
                <CardDescription>PostgreSQL and Redis status</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm text-muted-foreground">
                      PostgreSQL Connections
                    </span>
                    <span className="font-mono font-medium">
                      {systemMetrics.database.connections}/
                      {systemMetrics.database.maxConnections}
                    </span>
                  </div>
                  <Progress
                    value={
                      (systemMetrics.database.connections /
                        systemMetrics.database.maxConnections) *
                      100
                    }
                  />
                </div>
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm text-muted-foreground">
                      Redis Memory
                    </span>
                    <span className="font-mono font-medium">
                      {systemMetrics.redis.memoryUsed}GB /{" "}
                      {systemMetrics.redis.memoryMax}GB
                    </span>
                  </div>
                  <Progress
                    value={
                      (systemMetrics.redis.memoryUsed /
                        systemMetrics.redis.memoryMax) *
                      100
                    }
                  />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">
                    Cache Hit Rate
                  </span>
                  <span className="font-mono font-medium text-green-600">
                    {systemMetrics.redis.hitRate}%
                  </span>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Traffic Chart Placeholder */}
          <Card>
            <CardHeader>
              <CardTitle>Traffic Overview</CardTitle>
              <CardDescription>Requests per second over time</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-center h-64 text-muted-foreground">
                <div className="text-center">
                  <BarChart3 className="h-16 w-16 mx-auto mb-4 opacity-50" />
                  <p>Traffic chart would be displayed here</p>
                  <p className="text-sm">Integration with Grafana/Prometheus</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="workers" className="space-y-6 mt-6">
          <div className="grid gap-4 md:grid-cols-3">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">
                  Total Workers
                </CardTitle>
                <Server className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{workerNodes.length}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">
                  Avg CPU Usage
                </CardTitle>
                <Cpu className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {systemMetrics.workers.avgCpu}%
                </div>
                <Progress
                  value={systemMetrics.workers.avgCpu}
                  className="mt-2"
                />
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">
                  Avg Memory Usage
                </CardTitle>
                <HardDrive className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {systemMetrics.workers.avgMemory}%
                </div>
                <Progress
                  value={systemMetrics.workers.avgMemory}
                  className="mt-2"
                />
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Worker Nodes</CardTitle>
              <CardDescription>
                XDP worker status across regions
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {workerNodes.map((worker) => (
                  <div
                    key={worker.id}
                    className="flex items-center justify-between p-4 rounded-lg border"
                  >
                    <div className="flex items-center gap-4">
                      <div
                        className={`w-3 h-3 rounded-full ${
                          worker.status === "healthy"
                            ? "bg-green-500"
                            : worker.status === "degraded"
                              ? "bg-yellow-500"
                              : "bg-red-500"
                        }`}
                      />
                      <div>
                        <p className="font-medium">{worker.hostname}</p>
                        <p className="text-sm text-muted-foreground">
                          {worker.region} · Uptime: {worker.uptime}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-8">
                      <div className="text-right">
                        <p className="text-sm font-medium">{worker.cpu}%</p>
                        <p className="text-xs text-muted-foreground">CPU</p>
                      </div>
                      <div className="text-right">
                        <p className="text-sm font-medium">{worker.memory}%</p>
                        <p className="text-xs text-muted-foreground">Memory</p>
                      </div>
                      <div className="text-right">
                        <p className="text-sm font-medium">
                          {worker.networkIn} Gbps
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Network In
                        </p>
                      </div>
                      <div className="text-right">
                        <p className="text-sm font-medium font-mono">
                          {formatNumber(worker.packetsPerSec)}
                        </p>
                        <p className="text-xs text-muted-foreground">pps</p>
                      </div>
                      <Badge
                        variant={
                          worker.status === "healthy"
                            ? "default"
                            : "destructive"
                        }
                      >
                        {worker.status}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="traffic" className="space-y-6 mt-6">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Peak RPS</CardTitle>
                <TrendingUp className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {formatNumber(systemMetrics.traffic.peakRps)}
                </div>
                <div className="text-xs text-muted-foreground">
                  Last 24 hours
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">
                  Total Requests
                </CardTitle>
                <Network className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {formatNumber(systemMetrics.traffic.totalRequests24h)}
                </div>
                <div className="text-xs text-muted-foreground">
                  Last 24 hours
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">
                  Total Bandwidth
                </CardTitle>
                <Wifi className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {formatBytes(systemMetrics.traffic.totalBytes24h)}
                </div>
                <div className="text-xs text-muted-foreground">
                  Last 24 hours
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">
                  p99 Latency
                </CardTitle>
                <Clock className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {systemMetrics.traffic.p99Latency}ms
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Traffic Distribution by Protocol</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {[
                  { protocol: "HTTP/2", percentage: 45, color: "bg-blue-500" },
                  {
                    protocol: "HTTP/3 (QUIC)",
                    percentage: 25,
                    color: "bg-purple-500",
                  },
                  {
                    protocol: "HTTP/1.1",
                    percentage: 15,
                    color: "bg-gray-500",
                  },
                  {
                    protocol: "Minecraft Java",
                    percentage: 10,
                    color: "bg-green-500",
                  },
                  {
                    protocol: "Minecraft Bedrock",
                    percentage: 5,
                    color: "bg-orange-500",
                  },
                ].map((item) => (
                  <div key={item.protocol}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm">{item.protocol}</span>
                      <span className="text-sm font-medium">
                        {item.percentage}%
                      </span>
                    </div>
                    <div className="h-2 rounded-full bg-muted overflow-hidden">
                      <div
                        className={`h-full ${item.color} rounded-full`}
                        style={{ width: `${item.percentage}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="infrastructure" className="space-y-6 mt-6">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Database className="h-5 w-5" />
                  PostgreSQL
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm text-muted-foreground">
                      Connections
                    </span>
                    <span className="font-mono">
                      {systemMetrics.database.connections}/
                      {systemMetrics.database.maxConnections}
                    </span>
                  </div>
                  <Progress
                    value={
                      (systemMetrics.database.connections /
                        systemMetrics.database.maxConnections) *
                      100
                    }
                  />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">
                    Query Latency
                  </span>
                  <span className="font-mono">
                    {systemMetrics.database.queryLatency}ms
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">
                    Cache Hit Rate
                  </span>
                  <span className="font-mono text-green-600">
                    {systemMetrics.database.cacheHitRate}%
                  </span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5" />
                  Redis
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm text-muted-foreground">
                      Memory
                    </span>
                    <span className="font-mono">
                      {systemMetrics.redis.memoryUsed}GB /{" "}
                      {systemMetrics.redis.memoryMax}GB
                    </span>
                  </div>
                  <Progress
                    value={
                      (systemMetrics.redis.memoryUsed /
                        systemMetrics.redis.memoryMax) *
                      100
                    }
                  />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">
                    Hit Rate
                  </span>
                  <span className="font-mono text-green-600">
                    {systemMetrics.redis.hitRate}%
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">
                    Operations/sec
                  </span>
                  <span className="font-mono">
                    {formatNumber(systemMetrics.redis.opsPerSec)}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">
                    Connections
                  </span>
                  <span className="font-mono">
                    {systemMetrics.redis.connections}
                  </span>
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Region Distribution</CardTitle>
              <CardDescription>Infrastructure across regions</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-3">
                {[
                  {
                    region: "EU-West",
                    workers: 2,
                    traffic: "35%",
                    status: "healthy",
                  },
                  {
                    region: "US-East",
                    workers: 2,
                    traffic: "45%",
                    status: "degraded",
                  },
                  {
                    region: "Asia-Pacific",
                    workers: 1,
                    traffic: "20%",
                    status: "healthy",
                  },
                ].map((region) => (
                  <div key={region.region} className="p-4 rounded-lg border">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium">{region.region}</span>
                      <Badge
                        variant={
                          region.status === "healthy"
                            ? "default"
                            : "destructive"
                        }
                      >
                        {region.status}
                      </Badge>
                    </div>
                    <div className="space-y-1 text-sm text-muted-foreground">
                      <p>{region.workers} workers</p>
                      <p>{region.traffic} of traffic</p>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
