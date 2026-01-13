import { createFileRoute } from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  ArrowUpDown,
  CheckCircle,
  ExternalLink,
  Eye,
  MoreHorizontal,
  Pause,
  Play,
  RefreshCw,
  Search,
  Server,
  Settings,
  Shield,
  Trash2,
  XCircle,
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export const Route = createFileRoute("/admin/backends")({
  component: AdminBackendsPage,
});

// Mock data for backends
const mockBackends = [
  {
    id: "be_1",
    name: "Production API",
    slug: "production-api",
    organizationId: "org_1",
    organizationName: "Acme Corp",
    status: "healthy",
    protocol: "HTTP/2",
    origins: [
      { host: "api-1.acme.com", port: 443, healthy: true },
      { host: "api-2.acme.com", port: 443, healthy: true },
    ],
    domains: ["api.acme.com", "api-v2.acme.com"],
    requestsToday: 1250000,
    bandwidthToday: 45.2, // GB
    activeConnections: 1523,
    avgLatencyMs: 45,
    createdAt: "2024-01-15T10:30:00Z",
    lastActiveAt: "2025-01-13T14:22:00Z",
  },
  {
    id: "be_2",
    name: "Game Server EU",
    slug: "game-server-eu",
    organizationId: "org_2",
    organizationName: "GameStudio Inc",
    status: "healthy",
    protocol: "Minecraft Java",
    origins: [
      { host: "mc-eu-1.gamestudio.net", port: 25565, healthy: true },
      { host: "mc-eu-2.gamestudio.net", port: 25565, healthy: true },
    ],
    domains: ["eu.play.gamestudio.net"],
    requestsToday: 890000,
    bandwidthToday: 23.8,
    activeConnections: 4521,
    avgLatencyMs: 12,
    createdAt: "2024-02-20T08:15:00Z",
    lastActiveAt: "2025-01-13T14:21:00Z",
  },
  {
    id: "be_3",
    name: "CDN Edge",
    slug: "cdn-edge",
    organizationId: "org_1",
    organizationName: "Acme Corp",
    status: "degraded",
    protocol: "HTTP/3",
    origins: [
      { host: "cdn-1.acme.com", port: 443, healthy: true },
      { host: "cdn-2.acme.com", port: 443, healthy: false },
      { host: "cdn-3.acme.com", port: 443, healthy: true },
    ],
    domains: ["cdn.acme.com", "static.acme.com", "assets.acme.com"],
    requestsToday: 5600000,
    bandwidthToday: 892.5,
    activeConnections: 8923,
    avgLatencyMs: 8,
    createdAt: "2024-01-10T12:00:00Z",
    lastActiveAt: "2025-01-13T14:22:30Z",
  },
  {
    id: "be_4",
    name: "Bedrock Server US",
    slug: "bedrock-us",
    organizationId: "org_3",
    organizationName: "MinecraftHost Pro",
    status: "healthy",
    protocol: "Minecraft Bedrock",
    origins: [{ host: "bedrock-us.mchost.pro", port: 19132, healthy: true }],
    domains: ["us.mchost.pro"],
    requestsToday: 340000,
    bandwidthToday: 12.3,
    activeConnections: 892,
    avgLatencyMs: 18,
    createdAt: "2024-03-05T16:45:00Z",
    lastActiveAt: "2025-01-13T14:20:00Z",
  },
  {
    id: "be_5",
    name: "Legacy API",
    slug: "legacy-api",
    organizationId: "org_4",
    organizationName: "OldTech Ltd",
    status: "offline",
    protocol: "HTTP/1.1",
    origins: [{ host: "api.oldtech.com", port: 80, healthy: false }],
    domains: ["api.oldtech.com"],
    requestsToday: 0,
    bandwidthToday: 0,
    activeConnections: 0,
    avgLatencyMs: 0,
    createdAt: "2023-06-15T09:00:00Z",
    lastActiveAt: "2025-01-10T08:30:00Z",
  },
];

function AdminBackendsPage() {
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [protocolFilter, setProtocolFilter] = useState<string>("all");
  const [selectedBackend, setSelectedBackend] = useState<
    (typeof mockBackends)[0] | null
  >(null);
  const [detailsOpen, setDetailsOpen] = useState(false);

  const filteredBackends = mockBackends.filter((backend) => {
    const matchesSearch =
      backend.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      backend.organizationName
        .toLowerCase()
        .includes(searchQuery.toLowerCase()) ||
      backend.domains.some((d) =>
        d.toLowerCase().includes(searchQuery.toLowerCase()),
      );
    const matchesStatus =
      statusFilter === "all" || backend.status === statusFilter;
    const matchesProtocol =
      protocolFilter === "all" || backend.protocol === protocolFilter;
    return matchesSearch && matchesStatus && matchesProtocol;
  });

  const stats = {
    total: mockBackends.length,
    healthy: mockBackends.filter((b) => b.status === "healthy").length,
    degraded: mockBackends.filter((b) => b.status === "degraded").length,
    offline: mockBackends.filter((b) => b.status === "offline").length,
    totalRequests: mockBackends.reduce((sum, b) => sum + b.requestsToday, 0),
    totalBandwidth: mockBackends.reduce((sum, b) => sum + b.bandwidthToday, 0),
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "healthy":
        return (
          <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
            <CheckCircle className="h-3 w-3 mr-1" />
            Healthy
          </Badge>
        );
      case "degraded":
        return (
          <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">
            <AlertTriangle className="h-3 w-3 mr-1" />
            Degraded
          </Badge>
        );
      case "offline":
        return (
          <Badge className="bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">
            <XCircle className="h-3 w-3 mr-1" />
            Offline
          </Badge>
        );
      default:
        return <Badge variant="secondary">{status}</Badge>;
    }
  };

  const getProtocolBadge = (protocol: string) => {
    const colors: Record<string, string> = {
      "HTTP/1.1":
        "bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200",
      "HTTP/2": "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200",
      "HTTP/3":
        "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200",
      "Minecraft Java":
        "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
      "Minecraft Bedrock":
        "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200",
    };
    return (
      <Badge className={colors[protocol] || "bg-gray-100 text-gray-800"}>
        {protocol}
      </Badge>
    );
  };

  const formatNumber = (num: number) => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
    return num.toString();
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">
          Backend Management
        </h1>
        <p className="text-muted-foreground">
          Monitor and manage all backends across organizations
        </p>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Total Backends
            </CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Healthy</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">
              {stats.healthy}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Degraded</CardTitle>
            <AlertTriangle className="h-4 w-4 text-yellow-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-yellow-600">
              {stats.degraded}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Offline</CardTitle>
            <XCircle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">
              {stats.offline}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Requests Today
            </CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {formatNumber(stats.totalRequests)}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Bandwidth Today
            </CardTitle>
            <ArrowUpDown className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {stats.totalBandwidth.toFixed(1)} GB
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader>
          <CardTitle>All Backends</CardTitle>
          <CardDescription>
            View and manage backends from all organizations
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col sm:flex-row gap-4 mb-6">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search backends, organizations, domains..."
                className="pl-10"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                aria-label="Search backends, organizations, and domains"
              />
            </div>
            <Select value={statusFilter} onValueChange={(value) => setStatusFilter(value ?? "all")}>
              <SelectTrigger className="w-[150px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="healthy">Healthy</SelectItem>
                <SelectItem value="degraded">Degraded</SelectItem>
                <SelectItem value="offline">Offline</SelectItem>
              </SelectContent>
            </Select>
            <Select value={protocolFilter} onValueChange={(value) => setProtocolFilter(value ?? "all")}>
              <SelectTrigger className="w-[180px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Protocols</SelectItem>
                <SelectItem value="HTTP/1.1">HTTP/1.1</SelectItem>
                <SelectItem value="HTTP/2">HTTP/2</SelectItem>
                <SelectItem value="HTTP/3">HTTP/3</SelectItem>
                <SelectItem value="Minecraft Java">Minecraft Java</SelectItem>
                <SelectItem value="Minecraft Bedrock">
                  Minecraft Bedrock
                </SelectItem>
              </SelectContent>
            </Select>
            <Button
              variant="outline"
              size="icon"
              aria-label="Refresh backends list"
            >
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>

          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Backend</TableHead>
                  <TableHead>Organization</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Protocol</TableHead>
                  <TableHead className="text-right">Requests</TableHead>
                  <TableHead className="text-right">Bandwidth</TableHead>
                  <TableHead className="text-right">Connections</TableHead>
                  <TableHead className="text-right">Latency</TableHead>
                  <TableHead className="w-[50px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredBackends.map((backend) => (
                  <TableRow key={backend.id}>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-medium">{backend.name}</span>
                        <span className="text-xs text-muted-foreground">
                          {backend.domains[0]}
                          {backend.domains.length > 1 &&
                            ` +${backend.domains.length - 1}`}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>{backend.organizationName}</TableCell>
                    <TableCell>{getStatusBadge(backend.status)}</TableCell>
                    <TableCell>{getProtocolBadge(backend.protocol)}</TableCell>
                    <TableCell className="text-right font-mono">
                      {formatNumber(backend.requestsToday)}
                    </TableCell>
                    <TableCell className="text-right font-mono">
                      {backend.bandwidthToday.toFixed(1)} GB
                    </TableCell>
                    <TableCell className="text-right font-mono">
                      {formatNumber(backend.activeConnections)}
                    </TableCell>
                    <TableCell className="text-right font-mono">
                      {backend.avgLatencyMs > 0
                        ? `${backend.avgLatencyMs}ms`
                        : "-"}
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger
                          render={
                            <Button
                              variant="ghost"
                              size="icon"
                              aria-label={`Actions for ${backend.name}`}
                            />
                          }
                        >
                          <MoreHorizontal className="h-4 w-4" />
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuLabel>Actions</DropdownMenuLabel>
                          <DropdownMenuItem
                            onClick={() => {
                              setSelectedBackend(backend);
                              setDetailsOpen(true);
                            }}
                          >
                            <Eye className="h-4 w-4 mr-2" />
                            View Details
                          </DropdownMenuItem>
                          <DropdownMenuItem>
                            <Settings className="h-4 w-4 mr-2" />
                            Configure
                          </DropdownMenuItem>
                          <DropdownMenuItem>
                            <ExternalLink className="h-4 w-4 mr-2" />
                            View in Dashboard
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          {backend.status === "offline" ? (
                            <DropdownMenuItem>
                              <Play className="h-4 w-4 mr-2" />
                              Enable Backend
                            </DropdownMenuItem>
                          ) : (
                            <DropdownMenuItem>
                              <Pause className="h-4 w-4 mr-2" />
                              Disable Backend
                            </DropdownMenuItem>
                          )}
                          <DropdownMenuSeparator />
                          <DropdownMenuItem className="text-red-600">
                            <Trash2 className="h-4 w-4 mr-2" />
                            Delete Backend
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Backend Details Dialog */}
      <Dialog open={detailsOpen} onOpenChange={setDetailsOpen}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Server className="h-5 w-5" />
              {selectedBackend?.name}
            </DialogTitle>
            <DialogDescription>
              {selectedBackend?.slug} - {selectedBackend?.organizationName}
            </DialogDescription>
          </DialogHeader>

          {selectedBackend && (
            <Tabs defaultValue="overview" className="mt-4">
              <TabsList>
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="origins">Origins</TabsTrigger>
                <TabsTrigger value="domains">Domains</TabsTrigger>
                <TabsTrigger value="metrics">Metrics</TabsTrigger>
              </TabsList>

              <TabsContent value="overview" className="space-y-4 mt-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">Status</CardTitle>
                    </CardHeader>
                    <CardContent>
                      {getStatusBadge(selectedBackend.status)}
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">Protocol</CardTitle>
                    </CardHeader>
                    <CardContent>
                      {getProtocolBadge(selectedBackend.protocol)}
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">
                        Active Connections
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold">
                        {formatNumber(selectedBackend.activeConnections)}
                      </div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">Average Latency</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold">
                        {selectedBackend.avgLatencyMs}ms
                      </div>
                    </CardContent>
                  </Card>
                </div>

                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm">Today's Traffic</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div>
                      <div className="flex justify-between text-sm mb-2">
                        <span>Requests</span>
                        <span>
                          {formatNumber(selectedBackend.requestsToday)}
                        </span>
                      </div>
                      <Progress
                        value={Math.min(
                          100,
                          (selectedBackend.requestsToday / 10000000) * 100,
                        )}
                      />
                    </div>
                    <div>
                      <div className="flex justify-between text-sm mb-2">
                        <span>Bandwidth</span>
                        <span>
                          {selectedBackend.bandwidthToday.toFixed(1)} GB
                        </span>
                      </div>
                      <Progress
                        value={Math.min(
                          100,
                          (selectedBackend.bandwidthToday / 1000) * 100,
                        )}
                      />
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="origins" className="mt-4">
                <Card>
                  <CardHeader>
                    <CardTitle>Origin Servers</CardTitle>
                    <CardDescription>
                      {selectedBackend.origins.length} origin(s) configured
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {selectedBackend.origins.map((origin, idx) => (
                        <div
                          key={idx}
                          className="flex items-center justify-between p-3 rounded-lg border"
                        >
                          <div className="flex items-center gap-3">
                            <div
                              className={`w-2 h-2 rounded-full ${
                                origin.healthy ? "bg-green-500" : "bg-red-500"
                              }`}
                            />
                            <span className="font-mono text-sm">
                              {origin.host}:{origin.port}
                            </span>
                          </div>
                          <Badge
                            variant={origin.healthy ? "default" : "destructive"}
                          >
                            {origin.healthy ? "Healthy" : "Unhealthy"}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="domains" className="mt-4">
                <Card>
                  <CardHeader>
                    <CardTitle>Domains</CardTitle>
                    <CardDescription>
                      {selectedBackend.domains.length} domain(s) configured
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {selectedBackend.domains.map((domain, idx) => (
                        <div
                          key={idx}
                          className="flex items-center justify-between p-3 rounded-lg border"
                        >
                          <span className="font-mono text-sm">{domain}</span>
                          <Badge variant="secondary">
                            <Shield className="h-3 w-3 mr-1" />
                            Protected
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="metrics" className="mt-4">
                <Card>
                  <CardHeader>
                    <CardTitle>Real-time Metrics</CardTitle>
                    <CardDescription>Live traffic data</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center justify-center h-48 text-muted-foreground">
                      <div className="text-center">
                        <Activity className="h-12 w-12 mx-auto mb-2 opacity-50" />
                        <p>Metrics chart would be displayed here</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
