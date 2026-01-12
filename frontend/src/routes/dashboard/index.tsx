import { createFileRoute } from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  Server,
  Shield,
  TrendingUp,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";

export const Route = createFileRoute("/dashboard/")({
  component: DashboardOverview,
});

function DashboardOverview() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
        <p className="text-muted-foreground">
          Monitor your DDoS protection status and traffic analytics.
        </p>
      </div>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Protected Backends
            </CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">12</div>
            <p className="text-xs text-muted-foreground">
              <span className="text-green-500 inline-flex items-center">
                <ArrowUpRight className="h-3 w-3" /> +2
              </span>{" "}
              from last month
            </p>
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
            <div className="text-2xl font-bold">24</div>
            <p className="text-xs text-muted-foreground">
              <span className="text-green-500 inline-flex items-center">
                <ArrowUpRight className="h-3 w-3" /> +4
              </span>{" "}
              from last week
            </p>
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
            <div className="text-2xl font-bold">45.2K</div>
            <p className="text-xs text-muted-foreground">
              <span className="text-red-500 inline-flex items-center">
                <ArrowDownRight className="h-3 w-3" /> -12%
              </span>{" "}
              from last hour
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Blocked Threats
            </CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">1,284</div>
            <p className="text-xs text-muted-foreground">
              <span className="text-green-500 inline-flex items-center">
                <TrendingUp className="h-3 w-3" />
              </span>{" "}
              Last 24 hours
            </p>
          </CardContent>
        </Card>
      </div>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        <Card className="col-span-4">
          <CardHeader>
            <CardTitle>Protection Status</CardTitle>
            <CardDescription>
              Current status of your DDoS protection systems.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {[
              { name: "TCP Protection", desc: "SYN Flood, ACK Flood" },
              { name: "UDP Protection", desc: "Amplification, Flood" },
              { name: "HTTP Protection", desc: "L7 DDoS, Slowloris" },
              { name: "QUIC Protection", desc: "Initial Flood, Retry" },
            ].map((p, i) => (
              <div key={i} className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge variant="default" className="bg-green-500">
                      Active
                    </Badge>
                    <span className="text-sm font-medium">{p.name}</span>
                  </div>
                  <span className="text-sm text-muted-foreground">
                    {p.desc}
                  </span>
                </div>
                <Progress value={100} className="h-2" />
              </div>
            ))}
          </CardContent>
        </Card>
        <Card className="col-span-3">
          <CardHeader>
            <CardTitle>Recent Activity</CardTitle>
            <CardDescription>
              Latest detected threats and actions.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[
                {
                  type: "SYN Flood",
                  source: "185.220.101.x",
                  time: "2 min ago",
                  action: "Blocked",
                },
                {
                  type: "UDP Amplification",
                  source: "45.33.32.x",
                  time: "5 min ago",
                  action: "Rate Limited",
                },
                {
                  type: "HTTP Flood",
                  source: "192.168.1.x",
                  time: "12 min ago",
                  action: "Challenged",
                },
                {
                  type: "Port Scan",
                  source: "203.0.113.x",
                  time: "18 min ago",
                  action: "Blocked",
                },
              ].map((e, i) => (
                <div key={i} className="flex items-center justify-between">
                  <div className="space-y-1">
                    <p className="text-sm font-medium leading-none">{e.type}</p>
                    <p className="text-xs text-muted-foreground">
                      Source: {e.source}
                    </p>
                  </div>
                  <div className="text-right">
                    <Badge
                      variant={
                        e.action === "Blocked" ? "destructive" : "secondary"
                      }
                      className="text-xs"
                    >
                      {e.action}
                    </Badge>
                    <p className="text-xs text-muted-foreground mt-1">
                      {e.time}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
