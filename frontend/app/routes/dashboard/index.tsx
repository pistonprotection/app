import { createFileRoute } from "@tanstack/react-router";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  Shield,
  Zap,
  Server,
  AlertTriangle,
  TrendingUp,
  TrendingDown,
  Activity,
} from "lucide-react";

export const Route = createFileRoute("/dashboard/")({
  component: DashboardOverview,
});

function DashboardOverview() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground">
          Overview of your DDoS protection status
        </p>
      </div>

      {/* Protection Status */}
      <Card className="border-success/50 bg-success/5">
        <CardContent className="flex items-center gap-4 p-6">
          <div className="h-12 w-12 rounded-full bg-success/20 flex items-center justify-center">
            <Shield className="h-6 w-6 text-success" />
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-semibold">Protection Active</h2>
              <Badge variant="success">Operational</Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              All systems are functioning normally. No active attacks detected.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Total Requests
            </CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">2.4M</div>
            <div className="flex items-center text-xs text-muted-foreground">
              <TrendingUp className="mr-1 h-3 w-3 text-success" />
              +12.5% from last hour
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Blocked Attacks
            </CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">45.2K</div>
            <div className="flex items-center text-xs text-muted-foreground">
              <TrendingDown className="mr-1 h-3 w-3 text-success" />
              -8.3% from last hour
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Active Backends
            </CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">8 / 10</div>
            <div className="flex items-center text-xs text-muted-foreground">
              2 backends offline
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Avg Latency
            </CardTitle>
            <Zap className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">0.8ms</div>
            <div className="flex items-center text-xs text-muted-foreground">
              <TrendingDown className="mr-1 h-3 w-3 text-success" />
              -0.2ms from average
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Traffic & Attacks */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Traffic Distribution</CardTitle>
            <CardDescription>Breakdown by protocol</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span>TCP</span>
                <span className="font-medium">65%</span>
              </div>
              <Progress value={65} className="h-2" />
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span>UDP</span>
                <span className="font-medium">28%</span>
              </div>
              <Progress value={28} className="h-2" />
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span>QUIC</span>
                <span className="font-medium">5%</span>
              </div>
              <Progress value={5} className="h-2" />
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span>Other</span>
                <span className="font-medium">2%</span>
              </div>
              <Progress value={2} className="h-2" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recent Attacks</CardTitle>
            <CardDescription>Last 24 hours</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[
                {
                  type: "SYN Flood",
                  source: "185.x.x.x",
                  time: "2 hours ago",
                  mitigated: true,
                },
                {
                  type: "UDP Amplification",
                  source: "192.x.x.x",
                  time: "5 hours ago",
                  mitigated: true,
                },
                {
                  type: "Minecraft Bot",
                  source: "45.x.x.x",
                  time: "8 hours ago",
                  mitigated: true,
                },
              ].map((attack, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between p-3 rounded-lg bg-muted/50"
                >
                  <div className="flex items-center gap-3">
                    <div className="h-8 w-8 rounded-full bg-destructive/20 flex items-center justify-center">
                      <AlertTriangle className="h-4 w-4 text-destructive" />
                    </div>
                    <div>
                      <p className="font-medium text-sm">{attack.type}</p>
                      <p className="text-xs text-muted-foreground">
                        From {attack.source}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <Badge variant="success" className="text-xs">
                      Mitigated
                    </Badge>
                    <p className="text-xs text-muted-foreground mt-1">
                      {attack.time}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Backend Status */}
      <Card>
        <CardHeader>
          <CardTitle>Backend Status</CardTitle>
          <CardDescription>Health status of your protected servers</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {[
              { name: "mc.example.com", status: "healthy", latency: "12ms", traffic: "1.2K req/s" },
              { name: "web.example.com", status: "healthy", latency: "8ms", traffic: "3.5K req/s" },
              { name: "api.example.com", status: "degraded", latency: "45ms", traffic: "890 req/s" },
              { name: "game.example.com", status: "offline", latency: "-", traffic: "0 req/s" },
            ].map((backend) => (
              <div
                key={backend.name}
                className="flex items-center justify-between p-3 rounded-lg bg-muted/50"
              >
                <div className="flex items-center gap-3">
                  <div
                    className={`h-2 w-2 rounded-full ${
                      backend.status === "healthy"
                        ? "bg-success"
                        : backend.status === "degraded"
                        ? "bg-warning"
                        : "bg-destructive"
                    }`}
                  />
                  <span className="font-medium">{backend.name}</span>
                </div>
                <div className="flex items-center gap-6 text-sm text-muted-foreground">
                  <span>{backend.latency}</span>
                  <span>{backend.traffic}</span>
                  <Badge
                    variant={
                      backend.status === "healthy"
                        ? "success"
                        : backend.status === "degraded"
                        ? "warning"
                        : "destructive"
                    }
                  >
                    {backend.status}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
