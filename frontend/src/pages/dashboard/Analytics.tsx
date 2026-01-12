import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { metricsQueryOptions, type Metrics } from "@/lib/api";
import { formatNumber, formatBytes } from "@/lib/utils";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
  Legend,
} from "recharts";

// Mock data generator for different time ranges
const generateMockMetrics = (timeRange: string): Metrics => {
  const dataPoints = timeRange === "24h" ? 24 : timeRange === "7d" ? 7 : 30;
  const multiplier = timeRange === "24h" ? 1 : timeRange === "7d" ? 7 : 30;

  return {
    totalRequests: 12847293 * multiplier,
    blockedRequests: 284739 * multiplier,
    allowedRequests: 12562554 * multiplier,
    challengedRequests: 45000 * multiplier,
    avgResponseTime: 45,
    bandwidthIn: 1024 * 1024 * 1024 * 2.5 * multiplier,
    bandwidthOut: 1024 * 1024 * 1024 * 8.2 * multiplier,
    activeConnections: 1247,
    requestsPerSecond: 4521,
    topAttackTypes: [
      { type: "DDoS", count: 150000 * multiplier, percentage: 52.7 },
      { type: "SQL Injection", count: 45000 * multiplier, percentage: 15.8 },
      { type: "XSS", count: 32000 * multiplier, percentage: 11.2 },
      { type: "Bot Traffic", count: 28000 * multiplier, percentage: 9.8 },
      { type: "Other", count: 29739 * multiplier, percentage: 10.5 },
    ],
    trafficByCountry: [
      { country: "United States", countryCode: "US", requests: 5000000 * multiplier, blocked: 50000 * multiplier },
      { country: "Germany", countryCode: "DE", requests: 2000000 * multiplier, blocked: 20000 * multiplier },
      { country: "Japan", countryCode: "JP", requests: 1500000 * multiplier, blocked: 15000 * multiplier },
      { country: "United Kingdom", countryCode: "GB", requests: 1200000 * multiplier, blocked: 12000 * multiplier },
      { country: "France", countryCode: "FR", requests: 800000 * multiplier, blocked: 8000 * multiplier },
    ],
    requestsOverTime: Array.from({ length: dataPoints }, (_, i) => ({
      timestamp: timeRange === "24h" ? `${i}:00` : timeRange === "7d" ? `Day ${i + 1}` : `${i + 1}`,
      value: Math.floor(Math.random() * 500000) + 300000,
      blocked: Math.floor(Math.random() * 20000) + 5000,
      allowed: Math.floor(Math.random() * 480000) + 295000,
    })),
    responseTimeOverTime: Array.from({ length: dataPoints }, (_, i) => ({
      timestamp: timeRange === "24h" ? `${i}:00` : timeRange === "7d" ? `Day ${i + 1}` : `${i + 1}`,
      value: Math.floor(Math.random() * 30) + 30,
    })),
  };
};

export function Analytics() {
  const [timeRange, setTimeRange] = useState("24h");

  const { data: metrics, isLoading } = useQuery({
    ...metricsQueryOptions(timeRange),
    placeholderData: () => generateMockMetrics(timeRange),
  });

  const blockRate = metrics
    ? ((metrics.blockedRequests / metrics.totalRequests) * 100).toFixed(2)
    : "0";

  // Generate bandwidth over time data
  const bandwidthData = Array.from(
    { length: timeRange === "24h" ? 24 : timeRange === "7d" ? 7 : 30 },
    (_, i) => ({
      timestamp:
        timeRange === "24h"
          ? `${i}:00`
          : timeRange === "7d"
          ? `Day ${i + 1}`
          : `${i + 1}`,
      inbound: Math.floor(Math.random() * 500) + 100,
      outbound: Math.floor(Math.random() * 800) + 200,
    })
  );

  // Generate status code distribution
  const statusCodeData = [
    { name: "2xx", value: 85, color: "#10b981" },
    { name: "3xx", value: 5, color: "#06b6d4" },
    { name: "4xx", value: 7, color: "#f59e0b" },
    { name: "5xx", value: 3, color: "#ef4444" },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Analytics</h1>
          <p className="text-muted-foreground">
            Deep insights into your traffic and protection metrics
          </p>
        </div>
        <div className="flex items-center gap-4">
          <Select value={timeRange} onValueChange={setTimeRange}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="Select time range" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="24h">Last 24 Hours</SelectItem>
              <SelectItem value="7d">Last 7 Days</SelectItem>
              <SelectItem value="30d">Last 30 Days</SelectItem>
            </SelectContent>
          </Select>
          <Button variant="outline">Export Report</Button>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid gap-4 md:grid-cols-5">
        {[
          { label: "Total Requests", value: formatNumber(metrics?.totalRequests || 0) },
          { label: "Blocked", value: formatNumber(metrics?.blockedRequests || 0), variant: "destructive" as const },
          { label: "Challenged", value: formatNumber(metrics?.challengedRequests || 0), variant: "warning" as const },
          { label: "Block Rate", value: `${blockRate}%` },
          { label: "Avg Response", value: `${metrics?.avgResponseTime || 0}ms` },
        ].map((stat, index) => (
          <Card key={index}>
            <CardContent className="pt-6">
              <div className="text-sm text-muted-foreground">{stat.label}</div>
              <div className="flex items-center gap-2">
                <span className="text-2xl font-bold">{stat.value}</span>
                {stat.variant && <Badge variant={stat.variant}>{stat.variant === "destructive" ? "blocked" : "challenged"}</Badge>}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Main Charts */}
      <Tabs defaultValue="traffic" className="space-y-4">
        <TabsList>
          <TabsTrigger value="traffic">Traffic</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="performance">Performance</TabsTrigger>
          <TabsTrigger value="geographic">Geographic</TabsTrigger>
        </TabsList>

        {/* Traffic Tab */}
        <TabsContent value="traffic" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Request Volume</CardTitle>
                <CardDescription>
                  Total requests over time with blocked vs allowed breakdown
                </CardDescription>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <Skeleton className="h-[300px] w-full" />
                ) : (
                  <div className="h-[300px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={metrics?.requestsOverTime || []}>
                        <defs>
                          <linearGradient id="colorAllowed2" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.3} />
                            <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0} />
                          </linearGradient>
                          <linearGradient id="colorBlocked2" x1="0" y1="0" x2="0" y2="1">
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
                        />
                        <Legend />
                        <Area
                          type="monotone"
                          dataKey="allowed"
                          stroke="#8b5cf6"
                          fillOpacity={1}
                          fill="url(#colorAllowed2)"
                          name="Allowed"
                        />
                        <Area
                          type="monotone"
                          dataKey="blocked"
                          stroke="#ef4444"
                          fillOpacity={1}
                          fill="url(#colorBlocked2)"
                          name="Blocked"
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Bandwidth Usage</CardTitle>
                <CardDescription>
                  Inbound and outbound bandwidth over time (MB)
                </CardDescription>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <Skeleton className="h-[300px] w-full" />
                ) : (
                  <div className="h-[300px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={bandwidthData}>
                        <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                        <XAxis
                          dataKey="timestamp"
                          className="text-xs"
                          tick={{ fill: "hsl(var(--muted-foreground))" }}
                        />
                        <YAxis
                          className="text-xs"
                          tick={{ fill: "hsl(var(--muted-foreground))" }}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "hsl(var(--card))",
                            border: "1px solid hsl(var(--border))",
                            borderRadius: "8px",
                          }}
                        />
                        <Legend />
                        <Bar dataKey="inbound" fill="#8b5cf6" name="Inbound" />
                        <Bar dataKey="outbound" fill="#06b6d4" name="Outbound" />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Status Codes */}
          <Card>
            <CardHeader>
              <CardTitle>Response Status Codes</CardTitle>
              <CardDescription>Distribution of HTTP status codes</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-8">
                <div className="h-[200px] w-[200px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={statusCodeData}
                        cx="50%"
                        cy="50%"
                        innerRadius={50}
                        outerRadius={80}
                        paddingAngle={2}
                        dataKey="value"
                      >
                        {statusCodeData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  {statusCodeData.map((item) => (
                    <div key={item.name} className="flex items-center gap-2">
                      <div
                        className="h-3 w-3 rounded-full"
                        style={{ backgroundColor: item.color }}
                      />
                      <span className="text-sm font-medium">{item.name}</span>
                      <span className="text-sm text-muted-foreground">
                        {item.value}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Security Tab */}
        <TabsContent value="security" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Threat Distribution</CardTitle>
                <CardDescription>Types of blocked threats</CardDescription>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <Skeleton className="h-[300px] w-full" />
                ) : (
                  <div className="h-[300px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={metrics?.topAttackTypes || []}
                        layout="vertical"
                      >
                        <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                        <XAxis
                          type="number"
                          className="text-xs"
                          tick={{ fill: "hsl(var(--muted-foreground))" }}
                          tickFormatter={(value) => formatNumber(value)}
                        />
                        <YAxis
                          type="category"
                          dataKey="type"
                          className="text-xs"
                          tick={{ fill: "hsl(var(--muted-foreground))" }}
                          width={100}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "hsl(var(--card))",
                            border: "1px solid hsl(var(--border))",
                            borderRadius: "8px",
                          }}
                          formatter={(value) => formatNumber(Number(value))}
                        />
                        <Bar dataKey="count" fill="#ef4444" radius={[0, 4, 4, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Attack Timeline</CardTitle>
                <CardDescription>Blocked requests over time</CardDescription>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <Skeleton className="h-[300px] w-full" />
                ) : (
                  <div className="h-[300px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={metrics?.requestsOverTime || []}>
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
                        />
                        <Line
                          type="monotone"
                          dataKey="blocked"
                          stroke="#ef4444"
                          strokeWidth={2}
                          dot={false}
                          name="Blocked Requests"
                        />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Top Blocked IPs/Countries */}
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Top Blocked Countries</CardTitle>
                <CardDescription>Countries with most blocked requests</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {(metrics?.trafficByCountry || []).map((country) => (
                    <div
                      key={country.countryCode}
                      className="flex items-center justify-between"
                    >
                      <div className="flex items-center gap-3">
                        <span className="text-lg">{getCountryFlag(country.countryCode)}</span>
                        <span className="font-medium">{country.country}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="destructive">
                          {formatNumber(country.blocked)} blocked
                        </Badge>
                        <span className="text-sm text-muted-foreground">
                          ({((country.blocked / country.requests) * 100).toFixed(1)}%)
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Security Summary</CardTitle>
                <CardDescription>Key security metrics</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Total Threats Blocked</span>
                    <span className="text-2xl font-bold text-destructive">
                      {formatNumber(metrics?.blockedRequests || 0)}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Challenges Issued</span>
                    <span className="text-2xl font-bold text-yellow-500">
                      {formatNumber(metrics?.challengedRequests || 0)}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Block Rate</span>
                    <span className="text-2xl font-bold">{blockRate}%</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Top Attack Vector</span>
                    <Badge variant="outline">
                      {metrics?.topAttackTypes[0]?.type || "N/A"}
                    </Badge>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Performance Tab */}
        <TabsContent value="performance" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Response Time</CardTitle>
                <CardDescription>Average response time over time (ms)</CardDescription>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <Skeleton className="h-[300px] w-full" />
                ) : (
                  <div className="h-[300px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={metrics?.responseTimeOverTime || []}>
                        <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                        <XAxis
                          dataKey="timestamp"
                          className="text-xs"
                          tick={{ fill: "hsl(var(--muted-foreground))" }}
                        />
                        <YAxis
                          className="text-xs"
                          tick={{ fill: "hsl(var(--muted-foreground))" }}
                          domain={[0, 100]}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "hsl(var(--card))",
                            border: "1px solid hsl(var(--border))",
                            borderRadius: "8px",
                          }}
                          formatter={(value) => `${value}ms`}
                        />
                        <Line
                          type="monotone"
                          dataKey="value"
                          stroke="#8b5cf6"
                          strokeWidth={2}
                          dot={false}
                          name="Response Time"
                        />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Performance Metrics</CardTitle>
                <CardDescription>Key performance indicators</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-6">
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Average Response Time</span>
                    <span className="text-2xl font-bold">
                      {metrics?.avgResponseTime || 0}ms
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Requests per Second</span>
                    <span className="text-2xl font-bold">
                      {formatNumber(metrics?.requestsPerSecond || 0)}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Active Connections</span>
                    <span className="text-2xl font-bold">
                      {formatNumber(metrics?.activeConnections || 0)}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm">Total Bandwidth</span>
                    <span className="text-2xl font-bold">
                      {formatBytes(
                        (metrics?.bandwidthIn || 0) + (metrics?.bandwidthOut || 0)
                      )}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Geographic Tab */}
        <TabsContent value="geographic" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Traffic by Country</CardTitle>
              <CardDescription>
                Geographic distribution of requests
              </CardDescription>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <Skeleton className="h-[400px] w-full" />
              ) : (
                <div className="h-[400px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={metrics?.trafficByCountry || []}>
                      <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
                      <XAxis
                        dataKey="country"
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
                        formatter={(value) => formatNumber(Number(value))}
                      />
                      <Legend />
                      <Bar
                        dataKey="requests"
                        fill="#8b5cf6"
                        name="Total Requests"
                        radius={[4, 4, 0, 0]}
                      />
                      <Bar
                        dataKey="blocked"
                        fill="#ef4444"
                        name="Blocked"
                        radius={[4, 4, 0, 0]}
                      />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Country Details */}
          <div className="grid gap-4 md:grid-cols-2">
            {(metrics?.trafficByCountry || []).slice(0, 4).map((country) => (
              <Card key={country.countryCode}>
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className="text-3xl">{getCountryFlag(country.countryCode)}</span>
                      <div>
                        <div className="font-semibold">{country.country}</div>
                        <div className="text-sm text-muted-foreground">
                          {country.countryCode}
                        </div>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-2xl font-bold">
                        {formatNumber(country.requests)}
                      </div>
                      <div className="text-sm text-destructive">
                        {formatNumber(country.blocked)} blocked
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
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
