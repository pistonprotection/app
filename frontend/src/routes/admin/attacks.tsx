import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import {
  AlertTriangle,
  ArrowDown,
  ArrowUp,
  Ban,
  Calendar,
  ChevronDown,
  Clock,
  Eye,
  Filter,
  Globe,
  MoreHorizontal,
  Network,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  TrendingUp,
  Zap,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";

export const Route = createFileRoute("/admin/attacks")({
  component: AdminAttacksPage,
});

// Mock attack data
const mockAttacks = [
  {
    id: "atk_1",
    backendId: "be_1",
    backendName: "Production API",
    organizationName: "Acme Corp",
    type: "HTTP Flood",
    layer: "L7",
    status: "mitigated",
    severity: "high",
    peakPps: 2500000,
    peakBps: 4500000000, // 4.5 Gbps
    totalPackets: 45000000000,
    totalBytes: 82000000000000,
    sourceCount: 12500,
    topSourceCountry: "CN",
    startedAt: "2025-01-13T08:15:00Z",
    endedAt: "2025-01-13T08:45:00Z",
    duration: 30, // minutes
    mitigationRule: "Rate limiting + geo-blocking",
  },
  {
    id: "atk_2",
    backendId: "be_2",
    backendName: "Game Server EU",
    organizationName: "GameStudio Inc",
    type: "UDP Amplification",
    layer: "L4",
    status: "ongoing",
    severity: "critical",
    peakPps: 8500000,
    peakBps: 12000000000, // 12 Gbps
    totalPackets: 180000000000,
    totalBytes: 250000000000000,
    sourceCount: 45000,
    topSourceCountry: "RU",
    startedAt: "2025-01-13T14:00:00Z",
    endedAt: null,
    duration: 22,
    mitigationRule: "UDP filter + packet validation",
  },
  {
    id: "atk_3",
    backendId: "be_3",
    backendName: "CDN Edge",
    organizationName: "Acme Corp",
    type: "SYN Flood",
    layer: "L4",
    status: "mitigated",
    severity: "medium",
    peakPps: 1200000,
    peakBps: 800000000, // 800 Mbps
    totalPackets: 8500000000,
    totalBytes: 5800000000000,
    sourceCount: 8200,
    topSourceCountry: "BR",
    startedAt: "2025-01-12T22:30:00Z",
    endedAt: "2025-01-12T23:15:00Z",
    duration: 45,
    mitigationRule: "SYN cookie + rate limiting",
  },
  {
    id: "atk_4",
    backendId: "be_4",
    backendName: "Bedrock Server US",
    organizationName: "MinecraftHost Pro",
    type: "Minecraft Bot Attack",
    layer: "L7",
    status: "mitigated",
    severity: "low",
    peakPps: 150000,
    peakBps: 120000000, // 120 Mbps
    totalPackets: 450000000,
    totalBytes: 380000000000,
    sourceCount: 2500,
    topSourceCountry: "US",
    startedAt: "2025-01-13T10:00:00Z",
    endedAt: "2025-01-13T10:20:00Z",
    duration: 20,
    mitigationRule: "Protocol validation + rate limiting",
  },
  {
    id: "atk_5",
    backendId: "be_1",
    backendName: "Production API",
    organizationName: "Acme Corp",
    type: "Slowloris",
    layer: "L7",
    status: "blocked",
    severity: "medium",
    peakPps: 50000,
    peakBps: 25000000, // 25 Mbps
    totalPackets: 120000000,
    totalBytes: 60000000000,
    sourceCount: 850,
    topSourceCountry: "IN",
    startedAt: "2025-01-11T14:00:00Z",
    endedAt: "2025-01-11T14:30:00Z",
    duration: 30,
    mitigationRule: "Connection timeout + header validation",
  },
];

function AdminAttacksPage() {
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [layerFilter, setLayerFilter] = useState<string>("all");
  const [selectedAttack, setSelectedAttack] = useState<
    (typeof mockAttacks)[0] | null
  >(null);
  const [detailsOpen, setDetailsOpen] = useState(false);

  const filteredAttacks = mockAttacks.filter((attack) => {
    const matchesSearch =
      attack.backendName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      attack.organizationName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      attack.type.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus =
      statusFilter === "all" || attack.status === statusFilter;
    const matchesSeverity =
      severityFilter === "all" || attack.severity === severityFilter;
    const matchesLayer = layerFilter === "all" || attack.layer === layerFilter;
    return matchesSearch && matchesStatus && matchesSeverity && matchesLayer;
  });

  const stats = {
    total: mockAttacks.length,
    ongoing: mockAttacks.filter((a) => a.status === "ongoing").length,
    mitigated: mockAttacks.filter((a) => a.status === "mitigated").length,
    blocked: mockAttacks.filter((a) => a.status === "blocked").length,
    critical: mockAttacks.filter((a) => a.severity === "critical").length,
    totalPackets: mockAttacks.reduce((sum, a) => sum + a.totalPackets, 0),
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "ongoing":
        return (
          <Badge className="bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200 animate-pulse">
            <Zap className="h-3 w-3 mr-1" />
            Ongoing
          </Badge>
        );
      case "mitigated":
        return (
          <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
            <ShieldCheck className="h-3 w-3 mr-1" />
            Mitigated
          </Badge>
        );
      case "blocked":
        return (
          <Badge className="bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
            <Ban className="h-3 w-3 mr-1" />
            Blocked
          </Badge>
        );
      default:
        return <Badge variant="secondary">{status}</Badge>;
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "critical":
        return (
          <Badge className="bg-red-600 text-white">
            <AlertTriangle className="h-3 w-3 mr-1" />
            Critical
          </Badge>
        );
      case "high":
        return (
          <Badge className="bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200">
            High
          </Badge>
        );
      case "medium":
        return (
          <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">
            Medium
          </Badge>
        );
      case "low":
        return (
          <Badge className="bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200">
            Low
          </Badge>
        );
      default:
        return <Badge variant="secondary">{severity}</Badge>;
    }
  };

  const formatBps = (bps: number) => {
    if (bps >= 1000000000000) return `${(bps / 1000000000000).toFixed(1)} Tbps`;
    if (bps >= 1000000000) return `${(bps / 1000000000).toFixed(1)} Gbps`;
    if (bps >= 1000000) return `${(bps / 1000000).toFixed(1)} Mbps`;
    if (bps >= 1000) return `${(bps / 1000).toFixed(1)} Kbps`;
    return `${bps} bps`;
  };

  const formatPps = (pps: number) => {
    if (pps >= 1000000) return `${(pps / 1000000).toFixed(1)}M`;
    if (pps >= 1000) return `${(pps / 1000).toFixed(1)}K`;
    return pps.toString();
  };

  const formatBytes = (bytes: number) => {
    if (bytes >= 1000000000000) return `${(bytes / 1000000000000).toFixed(1)} TB`;
    if (bytes >= 1000000000) return `${(bytes / 1000000000).toFixed(1)} GB`;
    if (bytes >= 1000000) return `${(bytes / 1000000).toFixed(1)} MB`;
    return `${bytes} bytes`;
  };

  const formatTime = (isoString: string) => {
    return new Date(isoString).toLocaleString();
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Attack Monitor</h1>
        <p className="text-muted-foreground">
          Real-time DDoS attack detection and mitigation status
        </p>
      </div>

      {/* Alert Banner for Ongoing Attacks */}
      {stats.ongoing > 0 && (
        <Card className="border-red-500 bg-red-50 dark:bg-red-950">
          <CardContent className="flex items-center gap-4 py-4">
            <div className="p-2 rounded-full bg-red-100 dark:bg-red-900">
              <ShieldAlert className="h-6 w-6 text-red-600 dark:text-red-400 animate-pulse" />
            </div>
            <div className="flex-1">
              <p className="font-semibold text-red-900 dark:text-red-100">
                {stats.ongoing} Active Attack{stats.ongoing > 1 ? "s" : ""} Detected
              </p>
              <p className="text-sm text-red-700 dark:text-red-300">
                Mitigation in progress. All systems are actively defending.
              </p>
            </div>
            <Button variant="destructive">View Active Attacks</Button>
          </CardContent>
        </Card>
      )}

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-6">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Attacks</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
            <p className="text-xs text-muted-foreground">Last 7 days</p>
          </CardContent>
        </Card>
        <Card className={stats.ongoing > 0 ? "border-red-500" : ""}>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Ongoing</CardTitle>
            <Zap className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${stats.ongoing > 0 ? "text-red-600" : ""}`}>
              {stats.ongoing}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Mitigated</CardTitle>
            <ShieldCheck className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{stats.mitigated}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Blocked</CardTitle>
            <Ban className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-600">{stats.blocked}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Critical</CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">{stats.critical}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Packets</CardTitle>
            <Network className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{formatPps(stats.totalPackets)}</div>
          </CardContent>
        </Card>
      </div>

      {/* Attacks Table */}
      <Card>
        <CardHeader>
          <CardTitle>Attack History</CardTitle>
          <CardDescription>
            All detected attacks across the platform
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col sm:flex-row gap-4 mb-6">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search attacks, backends, organizations..."
                className="pl-10"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="ongoing">Ongoing</SelectItem>
                <SelectItem value="mitigated">Mitigated</SelectItem>
                <SelectItem value="blocked">Blocked</SelectItem>
              </SelectContent>
            </Select>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severity</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
            <Select value={layerFilter} onValueChange={setLayerFilter}>
              <SelectTrigger className="w-[120px]">
                <SelectValue placeholder="Layer" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Layers</SelectItem>
                <SelectItem value="L4">Layer 4</SelectItem>
                <SelectItem value="L7">Layer 7</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline" size="icon">
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>

          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Attack Type</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Layer</TableHead>
                  <TableHead className="text-right">Peak Rate</TableHead>
                  <TableHead className="text-right">Sources</TableHead>
                  <TableHead>Started</TableHead>
                  <TableHead className="w-[50px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredAttacks.map((attack) => (
                  <TableRow
                    key={attack.id}
                    className={attack.status === "ongoing" ? "bg-red-50 dark:bg-red-950/20" : ""}
                  >
                    <TableCell>
                      <span className="font-medium">{attack.type}</span>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col">
                        <span>{attack.backendName}</span>
                        <span className="text-xs text-muted-foreground">
                          {attack.organizationName}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>{getStatusBadge(attack.status)}</TableCell>
                    <TableCell>{getSeverityBadge(attack.severity)}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{attack.layer}</Badge>
                    </TableCell>
                    <TableCell className="text-right font-mono">
                      <div className="flex flex-col items-end">
                        <span>{formatBps(attack.peakBps)}</span>
                        <span className="text-xs text-muted-foreground">
                          {formatPps(attack.peakPps)} pps
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Globe className="h-3 w-3 text-muted-foreground" />
                        <span>{attack.sourceCount.toLocaleString()}</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="text-sm">{formatTime(attack.startedAt)}</span>
                        <span className="text-xs text-muted-foreground">
                          {attack.duration}m duration
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuLabel>Actions</DropdownMenuLabel>
                          <DropdownMenuItem
                            onClick={() => {
                              setSelectedAttack(attack);
                              setDetailsOpen(true);
                            }}
                          >
                            <Eye className="h-4 w-4 mr-2" />
                            View Details
                          </DropdownMenuItem>
                          <DropdownMenuItem>
                            <Filter className="h-4 w-4 mr-2" />
                            View Filters
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem>
                            <Ban className="h-4 w-4 mr-2" />
                            Block Sources
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

      {/* Attack Details Dialog */}
      <Dialog open={detailsOpen} onOpenChange={setDetailsOpen}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5" />
              {selectedAttack?.type} Attack
            </DialogTitle>
            <DialogDescription>
              Target: {selectedAttack?.backendName} ({selectedAttack?.organizationName})
            </DialogDescription>
          </DialogHeader>

          {selectedAttack && (
            <Tabs defaultValue="overview" className="mt-4">
              <TabsList>
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="traffic">Traffic</TabsTrigger>
                <TabsTrigger value="sources">Sources</TabsTrigger>
                <TabsTrigger value="mitigation">Mitigation</TabsTrigger>
              </TabsList>

              <TabsContent value="overview" className="space-y-4 mt-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">Status</CardTitle>
                    </CardHeader>
                    <CardContent>
                      {getStatusBadge(selectedAttack.status)}
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">Severity</CardTitle>
                    </CardHeader>
                    <CardContent>
                      {getSeverityBadge(selectedAttack.severity)}
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">Duration</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="flex items-center gap-2">
                        <Clock className="h-4 w-4 text-muted-foreground" />
                        <span className="text-lg font-bold">
                          {selectedAttack.duration} minutes
                        </span>
                      </div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">Top Source Country</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="flex items-center gap-2">
                        <Globe className="h-4 w-4 text-muted-foreground" />
                        <span className="text-lg font-bold">
                          {selectedAttack.topSourceCountry}
                        </span>
                      </div>
                    </CardContent>
                  </Card>
                </div>

                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm">Timeline</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Started</span>
                        <span>{formatTime(selectedAttack.startedAt)}</span>
                      </div>
                      {selectedAttack.endedAt && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Ended</span>
                          <span>{formatTime(selectedAttack.endedAt)}</span>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="traffic" className="space-y-4 mt-4">
                <div className="grid gap-4 md:grid-cols-2">
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">Peak Bandwidth</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold">
                        {formatBps(selectedAttack.peakBps)}
                      </div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">Peak Packet Rate</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold">
                        {formatPps(selectedAttack.peakPps)} pps
                      </div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">Total Packets</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold">
                        {formatPps(selectedAttack.totalPackets)}
                      </div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader className="pb-2">
                      <CardTitle className="text-sm">Total Bytes</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="text-2xl font-bold">
                        {formatBytes(selectedAttack.totalBytes)}
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>

              <TabsContent value="sources" className="mt-4">
                <Card>
                  <CardHeader>
                    <CardTitle>Source IPs</CardTitle>
                    <CardDescription>
                      {selectedAttack.sourceCount.toLocaleString()} unique source IPs detected
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center justify-center h-48 text-muted-foreground">
                      <div className="text-center">
                        <Globe className="h-12 w-12 mx-auto mb-2 opacity-50" />
                        <p>Source IP distribution map would be displayed here</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="mitigation" className="mt-4">
                <Card>
                  <CardHeader>
                    <CardTitle>Mitigation Rules Applied</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="p-4 rounded-lg bg-muted">
                      <p className="font-mono text-sm">{selectedAttack.mitigationRule}</p>
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
