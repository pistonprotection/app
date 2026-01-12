import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Cloud,
  Database,
  FileWarning,
  Globe,
  Loader2,
  Network,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Wifi,
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { authClient } from "@/lib/auth-client";
import { useTRPC } from "@/lib/trpc/client";

export const Route = createFileRoute("/dashboard/ip-lookup")({
  component: IpLookupPage,
  head: () => ({
    meta: [
      { title: "IP Lookup - PistonProtection" },
      {
        name: "description",
        content: "Look up IP reputation scores and connection history",
      },
    ],
  }),
});

function IpLookupPage() {
  const [searchIp, setSearchIp] = useState("");
  const [submittedIp, setSubmittedIp] = useState("");
  const { data: session } = authClient.useSession();
  const trpc = useTRPC();
  const organizationId = session?.user?.id ?? "";

  // IP Score lookup
  const {
    data: ipScore,
    isLoading: scoreLoading,
    error: scoreError,
  } = useQuery({
    ...trpc.analytics.lookupIpScore.queryOptions({ ip: submittedIp }),
    enabled: submittedIp.length > 0,
  });

  // Connection history for this IP
  const { data: connectionHistory, isLoading: historyLoading } = useQuery({
    ...trpc.analytics.getConnectionsByIp.queryOptions({
      organizationId,
      sourceIp: submittedIp,
      hours: 168, // Last 7 days
    }),
    enabled: submittedIp.length > 0 && organizationId.length > 0,
  });

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (validateIp(searchIp)) {
      setSubmittedIp(searchIp.trim());
    }
  };

  const validateIp = (ip: string): boolean => {
    // IPv4 validation
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    // IPv6 validation (simplified)
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^::1$/;
    return ipv4Regex.test(ip.trim()) || ipv6Regex.test(ip.trim());
  };

  const getScoreColor = (score: number): string => {
    if (score >= 80) return "text-green-500";
    if (score >= 60) return "text-yellow-500";
    if (score >= 40) return "text-orange-500";
    return "text-red-500";
  };

  const getScoreBadge = (score: number) => {
    if (score >= 80)
      return (
        <Badge className="bg-green-500 text-white">
          <ShieldCheck className="h-3 w-3 mr-1" /> Trusted
        </Badge>
      );
    if (score >= 60)
      return (
        <Badge className="bg-yellow-500 text-white">
          <Shield className="h-3 w-3 mr-1" /> Neutral
        </Badge>
      );
    if (score >= 40)
      return (
        <Badge className="bg-orange-500 text-white">
          <ShieldAlert className="h-3 w-3 mr-1" /> Suspicious
        </Badge>
      );
    return (
      <Badge className="bg-red-500 text-white">
        <AlertTriangle className="h-3 w-3 mr-1" /> High Risk
      </Badge>
    );
  };

  const isLoading = scoreLoading || historyLoading;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">IP Lookup</h1>
        <p className="text-muted-foreground">
          Look up IP reputation scores and view connection history from your
          protected services.
        </p>
      </div>

      {/* Search Form */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Search className="h-5 w-5" />
            Search IP Address
          </CardTitle>
          <CardDescription>
            Enter an IPv4 or IPv6 address to look up its reputation score and
            connection history.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSearch} className="flex gap-4">
            <div className="flex-1">
              <Label htmlFor="ip-address" className="sr-only">
                IP Address
              </Label>
              <Input
                id="ip-address"
                type="text"
                placeholder="Enter IP address (e.g., 192.168.1.1)"
                value={searchIp}
                onChange={(e) => setSearchIp(e.target.value)}
                className="w-full"
              />
            </div>
            <Button type="submit" disabled={!searchIp || !validateIp(searchIp)}>
              {isLoading ? (
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
              ) : (
                <Search className="h-4 w-4 mr-2" />
              )}
              Lookup
            </Button>
          </form>
        </CardContent>
      </Card>

      {/* Results */}
      {submittedIp && (
        <>
          {scoreError && (
            <Card className="border-destructive">
              <CardContent className="pt-6">
                <div className="flex items-center gap-2 text-destructive">
                  <XCircle className="h-5 w-5" />
                  <span>Error looking up IP: {scoreError.message}</span>
                </div>
              </CardContent>
            </Card>
          )}

          {ipScore && (
            <div className="grid gap-6 md:grid-cols-2">
              {/* Score Card */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center justify-between">
                    <span className="flex items-center gap-2">
                      <Network className="h-5 w-5" />
                      IP Reputation
                    </span>
                    {getScoreBadge(ipScore.score)}
                  </CardTitle>
                  <CardDescription>{ipScore.ip}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">
                        Reputation Score
                      </span>
                      <span
                        className={`text-2xl font-bold ${getScoreColor(ipScore.score)}`}
                      >
                        {ipScore.score}/100
                      </span>
                    </div>
                    <Progress value={ipScore.score} className="h-3" />
                  </div>

                  <Separator />

                  <div className="grid grid-cols-2 gap-4">
                    <div className="flex items-center gap-2">
                      <Globe className="h-4 w-4 text-muted-foreground" />
                      <div>
                        <p className="text-sm font-medium">Country</p>
                        <p className="text-sm text-muted-foreground">
                          {ipScore.country ?? "Unknown"}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Database className="h-4 w-4 text-muted-foreground" />
                      <div>
                        <p className="text-sm font-medium">ASN</p>
                        <p className="text-sm text-muted-foreground">
                          {ipScore.asn ?? "Unknown"}
                        </p>
                      </div>
                    </div>
                  </div>

                  <Separator />

                  <div className="space-y-3">
                    <p className="text-sm font-medium">Risk Indicators</p>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="flex items-center gap-2">
                        {ipScore.isProxy ? (
                          <XCircle className="h-4 w-4 text-red-500" />
                        ) : (
                          <CheckCircle2 className="h-4 w-4 text-green-500" />
                        )}
                        <span className="text-sm">
                          {ipScore.isProxy ? "Proxy Detected" : "Not a Proxy"}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        {ipScore.isVpn ? (
                          <XCircle className="h-4 w-4 text-red-500" />
                        ) : (
                          <CheckCircle2 className="h-4 w-4 text-green-500" />
                        )}
                        <span className="text-sm">
                          {ipScore.isVpn ? "VPN Detected" : "Not a VPN"}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        {ipScore.isTor ? (
                          <XCircle className="h-4 w-4 text-red-500" />
                        ) : (
                          <CheckCircle2 className="h-4 w-4 text-green-500" />
                        )}
                        <span className="text-sm">
                          {ipScore.isTor
                            ? "Tor Exit Node"
                            : "Not a Tor Exit Node"}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        {ipScore.isDatacenter ? (
                          <FileWarning className="h-4 w-4 text-yellow-500" />
                        ) : (
                          <Wifi className="h-4 w-4 text-green-500" />
                        )}
                        <span className="text-sm">
                          {ipScore.isDatacenter
                            ? "Datacenter IP"
                            : "Residential IP"}
                        </span>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Connection Stats */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Clock className="h-5 w-5" />
                    Connection History
                  </CardTitle>
                  <CardDescription>Last 7 days of activity</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  {connectionHistory?.stats ? (
                    <>
                      <div className="grid grid-cols-3 gap-4 text-center">
                        <div>
                          <p className="text-2xl font-bold">
                            {connectionHistory.stats.total}
                          </p>
                          <p className="text-sm text-muted-foreground">
                            Total Connections
                          </p>
                        </div>
                        <div>
                          <p className="text-2xl font-bold text-green-500">
                            {connectionHistory.stats.successful}
                          </p>
                          <p className="text-sm text-muted-foreground">
                            Successful
                          </p>
                        </div>
                        <div>
                          <p className="text-2xl font-bold text-red-500">
                            {connectionHistory.stats.blocked}
                          </p>
                          <p className="text-sm text-muted-foreground">
                            Blocked
                          </p>
                        </div>
                      </div>

                      <Separator />

                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <p className="text-sm text-muted-foreground">
                            Bytes In
                          </p>
                          <p className="text-lg font-medium">
                            {formatBytes(connectionHistory.stats.bytesIn)}
                          </p>
                        </div>
                        <div>
                          <p className="text-sm text-muted-foreground">
                            Bytes Out
                          </p>
                          <p className="text-lg font-medium">
                            {formatBytes(connectionHistory.stats.bytesOut)}
                          </p>
                        </div>
                        <div>
                          <p className="text-sm text-muted-foreground">
                            Avg Latency
                          </p>
                          <p className="text-lg font-medium">
                            {connectionHistory.stats.avgLatency.toFixed(1)}ms
                          </p>
                        </div>
                        <div>
                          <p className="text-sm text-muted-foreground">
                            Block Rate
                          </p>
                          <p className="text-lg font-medium">
                            {connectionHistory.stats.total > 0
                              ? (
                                  (connectionHistory.stats.blocked /
                                    connectionHistory.stats.total) *
                                  100
                                ).toFixed(1)
                              : 0}
                            %
                          </p>
                        </div>
                      </div>
                    </>
                  ) : (
                    <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                      <Cloud className="h-8 w-8 mb-2" />
                      <p>No connection history found for this IP</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          )}

          {/* Recent Connection Attempts */}
          {connectionHistory?.recentAttempts &&
            connectionHistory.recentAttempts.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle>Recent Connection Attempts</CardTitle>
                  <CardDescription>
                    Most recent connections from {submittedIp}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Time</TableHead>
                        <TableHead>Backend</TableHead>
                        <TableHead>Protocol</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Latency</TableHead>
                        <TableHead>Bytes</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {connectionHistory.recentAttempts.map((attempt, i) => (
                        <TableRow key={i}>
                          <TableCell className="font-mono text-sm">
                            {new Date(attempt.timestamp).toLocaleString()}
                          </TableCell>
                          <TableCell>
                            {attempt.backend?.name ?? "Unknown"}
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline">
                              {attempt.protocol ?? "TCP"}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            {attempt.success ? (
                              <Badge className="bg-green-500 text-white">
                                <CheckCircle2 className="h-3 w-3 mr-1" />
                                Allowed
                              </Badge>
                            ) : (
                              <Badge className="bg-red-500 text-white">
                                <XCircle className="h-3 w-3 mr-1" />
                                Blocked
                              </Badge>
                            )}
                          </TableCell>
                          <TableCell>
                            {attempt.latencyMs
                              ? `${attempt.latencyMs.toFixed(1)}ms`
                              : "-"}
                          </TableCell>
                          <TableCell>
                            {formatBytes(
                              (attempt.bytesIn ?? 0) + (attempt.bytesOut ?? 0),
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            )}

          {/* No Results */}
          {!scoreLoading && !ipScore && (
            <Card>
              <CardContent className="pt-6">
                <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                  <Search className="h-12 w-12 mb-4" />
                  <p className="text-lg font-medium">No data found</p>
                  <p className="text-sm">
                    We don't have any information about this IP address yet.
                  </p>
                </div>
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* Tips Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Understanding IP Scores
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-4">
            <div className="space-y-1">
              <Badge className="bg-green-500 text-white">80-100</Badge>
              <p className="text-sm text-muted-foreground">
                Trusted. Low risk residential or business IP.
              </p>
            </div>
            <div className="space-y-1">
              <Badge className="bg-yellow-500 text-white">60-79</Badge>
              <p className="text-sm text-muted-foreground">
                Neutral. No significant risk factors detected.
              </p>
            </div>
            <div className="space-y-1">
              <Badge className="bg-orange-500 text-white">40-59</Badge>
              <p className="text-sm text-muted-foreground">
                Suspicious. May be associated with proxies or botnets.
              </p>
            </div>
            <div className="space-y-1">
              <Badge className="bg-red-500 text-white">0-39</Badge>
              <p className="text-sm text-muted-foreground">
                High risk. Known for malicious activity or attacks.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${Number.parseFloat((bytes / k ** i).toFixed(2))} ${sizes[i]}`;
}
