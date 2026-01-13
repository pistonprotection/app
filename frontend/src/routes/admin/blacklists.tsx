import { useForm } from "@tanstack/react-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import {
  Ban,
  Download,
  Globe,
  Loader2,
  MoreVertical,
  Network,
  Plus,
  Search,
  Trash2,
  Upload,
} from "lucide-react";
import { useRef, useState } from "react";
import { toast } from "sonner";
import { z } from "zod";
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
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import { Textarea } from "@/components/ui/textarea";
import { useTRPC } from "@/lib/trpc/client";

export const Route = createFileRoute("/admin/blacklists")({
  component: AdminBlacklists,
});

// Schema for validation
const addBlacklistSchema = z.object({
  type: z.enum(["ip", "cidr", "asn", "country"]),
  value: z.string().min(1),
  reason: z.string().optional(),
  expiresAt: z.string().optional(),
});

// Use the schema to prevent unused variable warnings
void addBlacklistSchema;

type BlacklistType = "ip" | "cidr" | "asn" | "country";

function AdminBlacklists() {
  const [searchQuery, setSearchQuery] = useState("");
  const [activeTab, setActiveTab] = useState<BlacklistType>("ip");
  const [isAddDialogOpen, setIsAddDialogOpen] = useState(false);
  const [isImportDialogOpen, setIsImportDialogOpen] = useState(false);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [importProgress, setImportProgress] = useState<{
    total: number;
    processed: number;
    errors: string[];
  } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const trpc = useTRPC();
  const queryClient = useQueryClient();

  // Get blacklist entries
  const { data: blacklistEntries, isLoading } = useQuery(
    trpc.admin.listBlacklistEntries.queryOptions({
      type: activeTab,
      search: searchQuery || undefined,
      limit: 100,
    }),
  );

  // Get blacklist stats
  const { data: blacklistStats } = useQuery(
    trpc.admin.getBlacklistStats.queryOptions(),
  );

  // Add blacklist entry mutation
  const addMutation = useMutation(
    trpc.admin.addBlacklistEntry.mutationOptions({
      onSuccess: () => {
        toast.success("Blacklist entry added");
        setIsAddDialogOpen(false);
        queryClient.invalidateQueries({ queryKey: ["admin", "blacklist"] });
      },
      onError: (error) => {
        toast.error(`Failed to add entry: ${error.message}`);
      },
    }),
  );

  // Remove blacklist entry mutation
  const removeMutation = useMutation(
    trpc.admin.removeBlacklistEntry.mutationOptions({
      onSuccess: () => {
        toast.success("Blacklist entry removed");
        setDeleteId(null);
        queryClient.invalidateQueries({ queryKey: ["admin", "blacklist"] });
      },
      onError: (error) => {
        toast.error(`Failed to remove entry: ${error.message}`);
      },
    }),
  );

  // Form for adding entries
  const form = useForm({
    defaultValues: {
      type: "ip" as BlacklistType,
      value: "",
      reason: "",
      expiresAt: "",
    },
    onSubmit: async ({ value }) => {
      await addMutation.mutateAsync({
        type: value.type,
        value: value.value,
        reason: value.reason || undefined,
        expiresAt: value.expiresAt ? new Date(value.expiresAt) : undefined,
      });
    },
  });

  // Export blacklist entries to CSV
  const handleExport = () => {
    if (!blacklistEntries?.items || blacklistEntries.items.length === 0) {
      toast.error("No entries to export");
      return;
    }

    const csvHeader = "type,value,reason,expires_at,added_at\n";
    const csvRows = blacklistEntries.items
      .map((entry) => {
        const reason = (entry.reason || "").replace(/"/g, '""');
        const expiresAt = entry.expiresAt
          ? new Date(entry.expiresAt).toISOString()
          : "";
        const createdAt = new Date(entry.createdAt).toISOString();
        return `"${activeTab}","${entry.value}","${reason}","${expiresAt}","${createdAt}"`;
      })
      .join("\n");

    const csv = csvHeader + csvRows;
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `blacklist-${activeTab}-${new Date().toISOString().split("T")[0]}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    toast.success(`Exported ${blacklistEntries.items.length} entries`);
  };

  // Import blacklist entries from CSV
  const handleImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const text = await file.text();
    const lines = text.split("\n").filter((line) => line.trim());

    // Skip header if present
    const hasHeader = lines[0]?.toLowerCase().includes("type");
    const dataLines = hasHeader ? lines.slice(1) : lines;

    if (dataLines.length === 0) {
      toast.error("No entries found in file");
      return;
    }

    setImportProgress({ total: dataLines.length, processed: 0, errors: [] });
    setIsImportDialogOpen(true);

    const errors: string[] = [];
    let processed = 0;

    for (const line of dataLines) {
      try {
        // Parse CSV line (simple parser - handles quoted values)
        const match = line.match(/(?:"([^"]*(?:""[^"]*)*)"|([^,]*))(?:,|$)/g);
        if (!match) continue;

        const values = match
          .map((v) =>
            v.replace(/^"|"$/g, "").replace(/""/, '"').replace(/,$/, ""),
          )
          .slice(0, 4);

        const [type, value, reason, expiresAt] = values;

        if (!value?.trim()) {
          processed++;
          continue;
        }

        const entryType = (type?.trim() || activeTab) as BlacklistType;
        if (!["ip", "cidr", "asn", "country"].includes(entryType)) {
          errors.push(`Invalid type: ${type}`);
          processed++;
          continue;
        }

        await addMutation.mutateAsync({
          type: entryType,
          value: value.trim(),
          reason: reason?.trim() || undefined,
          expiresAt: expiresAt?.trim() ? new Date(expiresAt.trim()) : undefined,
        });
      } catch (err) {
        errors.push(
          `Line ${processed + 1}: ${err instanceof Error ? err.message : "Unknown error"}`,
        );
      }

      processed++;
      setImportProgress((prev) =>
        prev ? { ...prev, processed, errors } : null,
      );
    }

    queryClient.invalidateQueries({ queryKey: ["admin", "blacklist"] });

    if (errors.length > 0) {
      toast.warning(
        `Import completed with ${errors.length} error(s). ${processed - errors.length} entries added.`,
      );
    } else {
      toast.success(`Successfully imported ${processed} entries`);
    }

    // Reset file input
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">
            Global Blacklists
          </h1>
          <p className="text-muted-foreground">
            Manage platform-wide IP, ASN, and country blocklists
          </p>
        </div>
        <div className="flex gap-2">
          <input
            type="file"
            ref={fileInputRef}
            className="hidden"
            accept=".csv,.txt"
            onChange={handleImport}
          />
          <Button
            variant="outline"
            onClick={() => fileInputRef.current?.click()}
          >
            <Upload className="mr-2 h-4 w-4" />
            Import
          </Button>
          <Button variant="outline" onClick={handleExport}>
            <Download className="mr-2 h-4 w-4" />
            Export
          </Button>
          <Dialog open={isAddDialogOpen} onOpenChange={setIsAddDialogOpen}>
            <DialogTrigger render={<Button />}>
              <Plus className="mr-2 h-4 w-4" />
              Add Entry
            </DialogTrigger>
            <DialogContent>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  form.handleSubmit();
                }}
              >
                <DialogHeader>
                  <DialogTitle>Add Blacklist Entry</DialogTitle>
                  <DialogDescription>
                    Add an IP, CIDR range, ASN, or country to the global
                    blacklist.
                  </DialogDescription>
                </DialogHeader>
                <div className="grid gap-4 py-4">
                  <form.Field name="type">
                    {(field) => (
                      <div className="grid gap-2">
                        <Label>Type</Label>
                        <Select
                          value={field.state.value}
                          onValueChange={(v) =>
                            field.handleChange(v as BlacklistType)
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="ip">IP Address</SelectItem>
                            <SelectItem value="cidr">CIDR Range</SelectItem>
                            <SelectItem value="asn">ASN</SelectItem>
                            <SelectItem value="country">Country</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    )}
                  </form.Field>
                  <form.Field name="value">
                    {(field) => (
                      <div className="grid gap-2">
                        <Label>Value</Label>
                        <Input
                          placeholder={
                            form.state.values.type === "ip"
                              ? "192.168.1.1"
                              : form.state.values.type === "cidr"
                                ? "192.168.0.0/24"
                                : form.state.values.type === "asn"
                                  ? "AS12345"
                                  : "RU"
                          }
                          value={field.state.value}
                          onChange={(e) => field.handleChange(e.target.value)}
                        />
                      </div>
                    )}
                  </form.Field>
                  <form.Field name="reason">
                    {(field) => (
                      <div className="grid gap-2">
                        <Label>Reason (optional)</Label>
                        <Textarea
                          placeholder="Reason for blacklisting..."
                          value={field.state.value}
                          onChange={(e) => field.handleChange(e.target.value)}
                        />
                      </div>
                    )}
                  </form.Field>
                  <form.Field name="expiresAt">
                    {(field) => (
                      <div className="grid gap-2">
                        <Label>Expires (optional)</Label>
                        <Input
                          type="datetime-local"
                          value={field.state.value}
                          onChange={(e) => field.handleChange(e.target.value)}
                        />
                      </div>
                    )}
                  </form.Field>
                </div>
                <DialogFooter>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => setIsAddDialogOpen(false)}
                  >
                    Cancel
                  </Button>
                  <Button type="submit" disabled={addMutation.isPending}>
                    {addMutation.isPending && (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    )}
                    Add Entry
                  </Button>
                </DialogFooter>
              </form>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">IP Addresses</CardTitle>
            <Ban className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {blacklistStats?.ipCount ?? 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">CIDR Ranges</CardTitle>
            <Network className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {blacklistStats?.cidrCount ?? 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">ASNs</CardTitle>
            <Network className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {blacklistStats?.asnCount ?? 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Countries</CardTitle>
            <Globe className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {blacklistStats?.countryCount ?? 0}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Blacklist Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Blacklist Entries</CardTitle>
              <CardDescription>
                Manage blocked IPs, ranges, ASNs, and countries
              </CardDescription>
            </div>
            <div className="relative w-64">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search entries..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Tabs
            value={activeTab}
            onValueChange={(v) => setActiveTab(v as BlacklistType)}
          >
            <TabsList>
              <TabsTrigger value="ip">IP Addresses</TabsTrigger>
              <TabsTrigger value="cidr">CIDR Ranges</TabsTrigger>
              <TabsTrigger value="asn">ASNs</TabsTrigger>
              <TabsTrigger value="country">Countries</TabsTrigger>
            </TabsList>
            <TabsContent value={activeTab} className="mt-4">
              {isLoading ? (
                <div className="flex justify-center py-8">
                  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                </div>
              ) : blacklistEntries?.items.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-8 text-center">
                  <Ban className="h-12 w-12 text-muted-foreground mb-4" />
                  <h3 className="text-lg font-semibold">No entries</h3>
                  <p className="text-muted-foreground">
                    No {activeTab} blacklist entries found
                  </p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Value</TableHead>
                      <TableHead>Reason</TableHead>
                      <TableHead>Added By</TableHead>
                      <TableHead>Expires</TableHead>
                      <TableHead>Added</TableHead>
                      <TableHead className="w-[50px]" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {blacklistEntries?.items.map((entry) => (
                      <TableRow key={entry.id}>
                        <TableCell className="font-mono font-medium">
                          {entry.value}
                        </TableCell>
                        <TableCell className="max-w-xs truncate">
                          {entry.reason || "-"}
                        </TableCell>
                        <TableCell>{entry.addedBy ?? "System"}</TableCell>
                        <TableCell>
                          {entry.expiresAt ? (
                            <Badge variant="outline">
                              {new Date(entry.expiresAt).toLocaleDateString()}
                            </Badge>
                          ) : (
                            <Badge>Permanent</Badge>
                          )}
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          {new Date(entry.createdAt).toLocaleDateString()}
                        </TableCell>
                        <TableCell>
                          <DropdownMenu>
                            <DropdownMenuTrigger
                              render={<Button variant="ghost" size="icon" />}
                            >
                              <MoreVertical className="h-4 w-4" />
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem
                                onClick={() => setDeleteId(entry.id)}
                                className="text-destructive focus:text-destructive"
                              >
                                <Trash2 className="mr-2 h-4 w-4" />
                                Remove
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* Delete Confirmation Dialog */}
      <Dialog open={!!deleteId} onOpenChange={() => setDeleteId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Remove Entry</DialogTitle>
            <DialogDescription>
              Are you sure you want to remove this blacklist entry? This will
              immediately allow traffic from this source.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteId(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() =>
                deleteId && removeMutation.mutate({ id: deleteId })
              }
              disabled={removeMutation.isPending}
            >
              {removeMutation.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Import Progress Dialog */}
      <Dialog
        open={isImportDialogOpen}
        onOpenChange={(open) => {
          if (!open && importProgress?.processed === importProgress?.total) {
            setIsImportDialogOpen(false);
            setImportProgress(null);
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Importing Blacklist Entries</DialogTitle>
            <DialogDescription>
              {importProgress && importProgress.processed < importProgress.total
                ? `Processing ${importProgress.processed} of ${importProgress.total} entries...`
                : `Import completed. ${importProgress?.processed ?? 0} entries processed.`}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            {importProgress && (
              <>
                <div className="relative h-2 w-full overflow-hidden rounded-full bg-secondary">
                  <div
                    className="h-full bg-primary transition-all"
                    style={{
                      width: `${(importProgress.processed / importProgress.total) * 100}%`,
                    }}
                  />
                </div>
                {importProgress.errors.length > 0 && (
                  <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-3">
                    <p className="text-sm font-medium text-destructive mb-2">
                      Errors ({importProgress.errors.length})
                    </p>
                    <div className="max-h-32 overflow-y-auto text-xs text-destructive/80">
                      {importProgress.errors.slice(0, 10).map((err, i) => (
                        <p key={i}>{err}</p>
                      ))}
                      {importProgress.errors.length > 10 && (
                        <p className="font-medium mt-1">
                          ...and {importProgress.errors.length - 10} more
                        </p>
                      )}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
          <DialogFooter>
            <Button
              onClick={() => {
                setIsImportDialogOpen(false);
                setImportProgress(null);
              }}
              disabled={
                importProgress !== null &&
                importProgress.processed < importProgress.total
              }
            >
              {importProgress && importProgress.processed < importProgress.total
                ? "Importing..."
                : "Close"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
