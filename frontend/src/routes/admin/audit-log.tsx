import { useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import {
  Calendar,
  ChevronLeft,
  ChevronRight,
  Clock,
  Download,
  Filter,
  History,
  Loader2,
  RefreshCw,
  Search,
  User,
} from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
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
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
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
import { useTRPC } from "@/lib/trpc/client";

export const Route = createFileRoute("/admin/audit-log")({
  component: AuditLogPage,
});

type AuditLogFilters = {
  action: string | null;
  resource: string | null;
  userId: string | null;
  startDate: Date | null;
  endDate: Date | null;
};

function AuditLogPage() {
  const trpc = useTRPC();
  const [page, setPage] = useState(0);
  const [searchQuery, setSearchQuery] = useState("");
  const [filters, setFilters] = useState<AuditLogFilters>({
    action: null,
    resource: null,
    userId: null,
    startDate: null,
    endDate: null,
  });

  const limit = 25;

  // Get available filters
  const { data: filterOptions } = useQuery(
    trpc.admin.getAuditLogFilters.queryOptions(),
  );

  // Get audit log entries
  const {
    data: auditLog,
    isLoading,
    refetch,
  } = useQuery(
    trpc.admin.listAuditLog.queryOptions({
      action: filters.action ?? undefined,
      resource: filters.resource ?? undefined,
      userId: filters.userId ?? undefined,
      startDate: filters.startDate ?? undefined,
      endDate: filters.endDate ?? undefined,
      limit,
      offset: page * limit,
    }),
  );

  const totalPages = Math.ceil((auditLog?.total ?? 0) / limit);

  // Export audit log to CSV
  const handleExport = () => {
    if (!auditLog?.logs || auditLog.logs.length === 0) {
      toast.error("No entries to export");
      return;
    }

    const csvHeader =
      "timestamp,action,resource,resource_id,user_email,user_name,organization,ip_address,details\n";
    const csvRows = auditLog.logs
      .map((log) => {
        const details = JSON.stringify(log.details ?? {}).replace(/"/g, '""');
        const timestamp = new Date(log.timestamp).toISOString();
        return `"${timestamp}","${log.action}","${log.resource}","${log.resourceId ?? ""}","${log.user?.email ?? "System"}","${log.user?.name ?? ""}","${log.organization?.name ?? ""}","${log.ipAddress ?? ""}","${details}"`;
      })
      .join("\n");

    const csv = csvHeader + csvRows;
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `audit-log-${new Date().toISOString().split("T")[0]}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    toast.success(`Exported ${auditLog.logs.length} entries`);
  };

  // Get badge color for action type
  const getActionBadgeColor = (action: string) => {
    if (action.startsWith("create") || action.startsWith("add")) {
      return "bg-green-500/10 text-green-600 border-green-500/20";
    }
    if (action.startsWith("delete") || action.startsWith("remove")) {
      return "bg-red-500/10 text-red-600 border-red-500/20";
    }
    if (action.startsWith("update") || action.startsWith("edit")) {
      return "bg-blue-500/10 text-blue-600 border-blue-500/20";
    }
    if (action.startsWith("ban") || action.startsWith("suspend")) {
      return "bg-orange-500/10 text-orange-600 border-orange-500/20";
    }
    if (action.startsWith("login") || action.startsWith("auth")) {
      return "bg-purple-500/10 text-purple-600 border-purple-500/20";
    }
    return "bg-gray-500/10 text-gray-600 border-gray-500/20";
  };

  // Format timestamp
  const formatTimestamp = (date: Date) => {
    const d = new Date(date);
    const now = new Date();
    const diff = now.getTime() - d.getTime();

    // If less than 24 hours, show relative time
    if (diff < 24 * 60 * 60 * 1000) {
      const hours = Math.floor(diff / (60 * 60 * 1000));
      if (hours < 1) {
        const minutes = Math.floor(diff / (60 * 1000));
        return `${minutes}m ago`;
      }
      return `${hours}h ago`;
    }

    // Otherwise show date
    return d.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  // Clear filters
  const clearFilters = () => {
    setFilters({
      action: null,
      resource: null,
      userId: null,
      startDate: null,
      endDate: null,
    });
    setPage(0);
  };

  const hasActiveFilters =
    filters.action ||
    filters.resource ||
    filters.userId ||
    filters.startDate ||
    filters.endDate;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Audit Log</h1>
          <p className="text-muted-foreground">
            Track all administrative actions and system events
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
          <Button variant="outline" onClick={handleExport}>
            <Download className="mr-2 h-4 w-4" />
            Export
          </Button>
        </div>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-muted-foreground" />
              <CardTitle className="text-base">Filters</CardTitle>
              {hasActiveFilters && (
                <Badge variant="secondary" className="ml-2">
                  Active
                </Badge>
              )}
            </div>
            {hasActiveFilters && (
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                Clear all
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-4">
            <div className="space-y-2">
              <span className="text-sm font-medium">Action</span>
              <Select
                value={filters.action ?? "all"}
                onValueChange={(v) =>
                  setFilters({
                    ...filters,
                    action: v === "all" ? null : v,
                  })
                }
              >
                <SelectTrigger>
                  <SelectValue placeholder="All actions" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All actions</SelectItem>
                  {filterOptions?.actions.map((action) => (
                    <SelectItem key={action} value={action}>
                      {action}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <span className="text-sm font-medium">Resource</span>
              <Select
                value={filters.resource ?? "all"}
                onValueChange={(v) =>
                  setFilters({
                    ...filters,
                    resource: v === "all" ? null : v,
                  })
                }
              >
                <SelectTrigger>
                  <SelectValue placeholder="All resources" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All resources</SelectItem>
                  {filterOptions?.resources.map((resource) => (
                    <SelectItem key={resource} value={resource}>
                      {resource}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <span className="text-sm font-medium">Start Date</span>
              <Popover>
                <PopoverTrigger asChild>
                  <Button
                    variant="outline"
                    className="w-full justify-start font-normal"
                  >
                    <Calendar className="mr-2 h-4 w-4" />
                    {filters.startDate
                      ? filters.startDate.toLocaleDateString()
                      : "Select date"}
                  </Button>
                </PopoverTrigger>
                <PopoverContent className="w-auto p-3" align="start">
                  <Input
                    type="date"
                    onChange={(e) =>
                      setFilters({
                        ...filters,
                        startDate: e.target.value
                          ? new Date(e.target.value)
                          : null,
                      })
                    }
                  />
                </PopoverContent>
              </Popover>
            </div>

            <div className="space-y-2">
              <span className="text-sm font-medium">End Date</span>
              <Popover>
                <PopoverTrigger asChild>
                  <Button
                    variant="outline"
                    className="w-full justify-start font-normal"
                  >
                    <Calendar className="mr-2 h-4 w-4" />
                    {filters.endDate
                      ? filters.endDate.toLocaleDateString()
                      : "Select date"}
                  </Button>
                </PopoverTrigger>
                <PopoverContent className="w-auto p-3" align="start">
                  <Input
                    type="date"
                    onChange={(e) =>
                      setFilters({
                        ...filters,
                        endDate: e.target.value
                          ? new Date(e.target.value)
                          : null,
                      })
                    }
                  />
                </PopoverContent>
              </Popover>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Audit Log Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <History className="h-5 w-5" />
                Activity Log
              </CardTitle>
              <CardDescription>
                Showing {auditLog?.logs?.length ?? 0} of {auditLog?.total ?? 0}{" "}
                entries
              </CardDescription>
            </div>
            <div className="relative w-64">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : auditLog?.logs?.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <History className="h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="text-lg font-semibold">No audit log entries</h3>
              <p className="text-muted-foreground">
                {hasActiveFilters
                  ? "Try adjusting your filters"
                  : "No activity recorded yet"}
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[160px]">Timestamp</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Resource</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Organization</TableHead>
                  <TableHead className="w-[120px]">IP Address</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {auditLog?.logs.map((log) => (
                  <TableRow key={log.id}>
                    <TableCell className="text-muted-foreground">
                      <div className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {formatTimestamp(log.timestamp)}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={getActionBadgeColor(log.action)}
                      >
                        {log.action}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div>
                        <span className="font-medium">{log.resource}</span>
                        {log.resourceId && (
                          <span className="text-xs text-muted-foreground block font-mono">
                            {log.resourceId.slice(0, 8)}...
                          </span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      {log.user ? (
                        <div className="flex items-center gap-2">
                          <User className="h-4 w-4 text-muted-foreground" />
                          <div>
                            <span className="font-medium">{log.user.name}</span>
                            <span className="text-xs text-muted-foreground block">
                              {log.user.email}
                            </span>
                          </div>
                        </div>
                      ) : (
                        <span className="text-muted-foreground">System</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {log.organization?.name ?? (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {log.ipAddress ?? "-"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between mt-4 pt-4 border-t">
              <div className="text-sm text-muted-foreground">
                Page {page + 1} of {totalPages}
              </div>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(Math.max(0, page - 1))}
                  disabled={page === 0}
                >
                  <ChevronLeft className="h-4 w-4 mr-1" />
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
                  disabled={page === totalPages - 1}
                >
                  Next
                  <ChevronRight className="h-4 w-4 ml-1" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
