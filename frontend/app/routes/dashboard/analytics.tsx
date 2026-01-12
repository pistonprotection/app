import { createFileRoute } from "@tanstack/react-router";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import {
  Activity,
  Globe,
  Shield,
  TrendingUp,
  Clock,
  AlertTriangle,
  Server,
  Zap,
} from "lucide-react";

export const Route = createFileRoute("/dashboard/analytics")({
  component: AnalyticsPage,
});

const topCountries = [
  { code: "US", name: "United States", requests: "1.2M", percentage: 35 },
  { code: "DE", name: "Germany", requests: "890K", percentage: 26 },
  { code: "GB", name: "United Kingdom", requests: "456K", percentage: 13 },
  { code: "FR", name: "France", requests: "321K", percentage: 9 },
  { code: "NL", name: "Netherlands", requests: "287K", percentage: 8 },
  { code: "Other", name: "Other", requests: "312K", percentage: 9 },
];

const attackTypes = [
  { type: "SYN Flood", count: "45.2K", percentage: 38 },
  { type: "UDP Amplification", count: "28.1K", percentage: 24 },
  { type: "Invalid Protocol", count: "18.5K", percentage: 16 },
  { type: "Bot Traffic", count: "14.2K", percentage: 12 },
  { type: "Other", count: "12.0K", percentage: 10 },
];

const recentEvents = [
  {
    time: "2 min ago",
    type: "attack",
    message: "SYN flood detected from 185.x.x.x - 45K PPS mitigated",
    severity: "warning",
  },
  {
    time: "15 min ago",
    type: "info",
    message: "Backend mc.example.com latency returned to normal",
    severity: "success",
  },
  {
    time: "32 min ago",
    type: "attack",
    message: "UDP amplification attack blocked - source: DNS servers",
    severity: "warning",
  },
  {
    time: "1 hour ago",
    type: "info",
    message: "New filter rule 'Block CN IPs' created",
    severity: "info",
  },
  {
    time: "2 hours ago",
    type: "attack",
    message: "Large-scale botnet attack mitigated - 2.5 Gbps",
    severity: "destructive",
  },
];

function AnalyticsPage() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Analytics</h1>
          <p className="text-muted-foreground">
            Traffic analysis and attack patterns
          </p>
        </div>
        <Select defaultValue="24h">
          <SelectTrigger className="w-[180px]">
            <SelectValue placeholder="Time range" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="1h">Last hour</SelectItem>
            <SelectItem value="24h">Last 24 hours</SelectItem>
            <SelectItem value="7d">Last 7 days</SelectItem>
            <SelectItem value="30d">Last 30 days</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Overview Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Requests</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">3.4M</div>
            <div className="flex items-center text-xs text-muted-foreground">
              <TrendingUp className="mr-1 h-3 w-3 text-success" />
              +15.2% from yesterday
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Attacks Blocked</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">118K</div>
            <div className="flex items-center text-xs text-muted-foreground">
              <TrendingUp className="mr-1 h-3 w-3 text-destructive" />
              +8.3% from yesterday
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Peak Bandwidth</CardTitle>
            <Zap className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">4.2 Gbps</div>
            <div className="flex items-center text-xs text-muted-foreground">
              <Clock className="mr-1 h-3 w-3" />
              at 14:32 UTC
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Unique IPs</CardTitle>
            <Globe className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">24.5K</div>
            <div className="flex items-center text-xs text-muted-foreground">
              <TrendingUp className="mr-1 h-3 w-3 text-success" />
              +5.1% from yesterday
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Charts Placeholder */}
      <Card>
        <CardHeader>
          <CardTitle>Traffic Over Time</CardTitle>
          <CardDescription>Requests and blocked traffic over the selected period</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="h-[300px] flex items-center justify-center bg-muted/50 rounded-lg">
            <div className="text-center text-muted-foreground">
              <Activity className="h-12 w-12 mx-auto mb-2 opacity-50" />
              <p>Traffic chart would render here with Recharts</p>
              <p className="text-sm">Connect to real metrics API for data</p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="geographic" className="space-y-4">
        <TabsList>
          <TabsTrigger value="geographic">Geographic</TabsTrigger>
          <TabsTrigger value="attacks">Attack Types</TabsTrigger>
          <TabsTrigger value="events">Recent Events</TabsTrigger>
        </TabsList>

        <TabsContent value="geographic" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Traffic by Country</CardTitle>
                <CardDescription>Top source countries</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {topCountries.map((country) => (
                  <div key={country.code} className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{country.name}</span>
                      </div>
                      <span className="text-muted-foreground">{country.requests}</span>
                    </div>
                    <Progress value={country.percentage} className="h-2" />
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Geographic Distribution</CardTitle>
                <CardDescription>World map visualization</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-[300px] flex items-center justify-center bg-muted/50 rounded-lg">
                  <div className="text-center text-muted-foreground">
                    <Globe className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p>World map would render here</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="attacks" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Attack Types</CardTitle>
                <CardDescription>Breakdown by attack category</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {attackTypes.map((attack) => (
                  <div key={attack.type} className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <div className="flex items-center gap-2">
                        <AlertTriangle className="h-4 w-4 text-destructive" />
                        <span className="font-medium">{attack.type}</span>
                      </div>
                      <span className="text-muted-foreground">{attack.count}</span>
                    </div>
                    <Progress value={attack.percentage} className="h-2" />
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Attack Timeline</CardTitle>
                <CardDescription>Attacks over time</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-[300px] flex items-center justify-center bg-muted/50 rounded-lg">
                  <div className="text-center text-muted-foreground">
                    <Shield className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p>Attack timeline chart would render here</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="events" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Recent Events</CardTitle>
              <CardDescription>Security events and system notifications</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {recentEvents.map((event, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-4 p-4 rounded-lg bg-muted/50"
                  >
                    <div
                      className={`h-8 w-8 rounded-full flex items-center justify-center ${
                        event.severity === "destructive"
                          ? "bg-destructive/20"
                          : event.severity === "warning"
                          ? "bg-warning/20"
                          : event.severity === "success"
                          ? "bg-success/20"
                          : "bg-primary/20"
                      }`}
                    >
                      {event.type === "attack" ? (
                        <AlertTriangle
                          className={`h-4 w-4 ${
                            event.severity === "destructive"
                              ? "text-destructive"
                              : "text-warning"
                          }`}
                        />
                      ) : (
                        <Activity
                          className={`h-4 w-4 ${
                            event.severity === "success"
                              ? "text-success"
                              : "text-primary"
                          }`}
                        />
                      )}
                    </div>
                    <div className="flex-1">
                      <p className="text-sm">{event.message}</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        {event.time}
                      </p>
                    </div>
                    <Badge
                      variant={
                        event.severity === "destructive"
                          ? "destructive"
                          : event.severity === "warning"
                          ? "warning"
                          : event.severity === "success"
                          ? "success"
                          : "secondary"
                      }
                    >
                      {event.type}
                    </Badge>
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
