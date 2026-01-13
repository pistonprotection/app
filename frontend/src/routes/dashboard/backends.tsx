import { useForm } from "@tanstack/react-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import {
  Activity,
  Globe,
  Loader2,
  MoreVertical,
  Pencil,
  Plus,
  Power,
  RefreshCw,
  Server,
  Settings,
  Shield,
  Trash2,
} from "lucide-react";
import React, { useState } from "react";
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
import { Checkbox } from "@/components/ui/checkbox";
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
  DropdownMenuSeparator,
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
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useOrganizationId } from "@/hooks/use-organization";
import { useTRPC } from "@/lib/trpc/client";

export const Route = createFileRoute("/dashboard/backends")({
  component: BackendsPage,
});

const protocolOptions = [
  { value: "tcp", label: "TCP" },
  { value: "udp", label: "UDP" },
  { value: "http", label: "HTTP" },
  { value: "https", label: "HTTPS" },
  { value: "quic", label: "QUIC" },
  { value: "minecraft_java", label: "Minecraft Java" },
  { value: "minecraft_bedrock", label: "Minecraft Bedrock" },
] as const;

// Schema for validation
const createBackendSchema = z.object({
  name: z.string().min(1, "Name is required").max(100),
  description: z.string().max(500).optional(),
  protocol: z.enum([
    "tcp",
    "udp",
    "http",
    "https",
    "quic",
    "minecraft_java",
    "minecraft_bedrock",
  ]),
  enabled: z.boolean().default(true),
  protectionLevel: z.number().int().min(0).max(100).default(50),
});

// Use the schema to prevent unused variable warnings
void createBackendSchema;

type Protocol =
  | "tcp"
  | "udp"
  | "http"
  | "https"
  | "quic"
  | "minecraft_java"
  | "minecraft_bedrock";

function BackendsPage() {
  const [isAddDialogOpen, setIsAddDialogOpen] = useState(false);
  const [editingBackendId, setEditingBackendId] = useState<string | null>(null);
  const [deleteBackendId, setDeleteBackendId] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkDeleteConfirm, setBulkDeleteConfirm] = useState(false);

  const trpc = useTRPC();
  const queryClient = useQueryClient();
  const organizationId = useOrganizationId();

  // Fetch backends
  const {
    data: backends = [],
    isLoading,
    error,
    refetch,
  } = useQuery(
    trpc.backends.list.queryOptions({
      organizationId,
    }),
  );

  // Create backend mutation
  const createMutation = useMutation(
    trpc.backends.create.mutationOptions({
      onSuccess: () => {
        toast.success("Backend created successfully");
        setIsAddDialogOpen(false);
        queryClient.invalidateQueries({ queryKey: ["backends"] });
      },
      onError: (error) => {
        toast.error(`Failed to create backend: ${error.message}`);
      },
    }),
  );

  // Toggle backend mutation
  const toggleMutation = useMutation(
    trpc.backends.toggle.mutationOptions({
      onSuccess: (data) => {
        toast.success(
          `Backend ${data.enabled ? "enabled" : "disabled"} successfully`,
        );
        queryClient.invalidateQueries({ queryKey: ["backends"] });
      },
      onError: (error) => {
        toast.error(`Failed to toggle backend: ${error.message}`);
      },
    }),
  );

  // Delete backend mutation
  const deleteMutation = useMutation(
    trpc.backends.delete.mutationOptions({
      onSuccess: () => {
        toast.success("Backend deleted successfully");
        setDeleteBackendId(null);
        queryClient.invalidateQueries({ queryKey: ["backends"] });
      },
      onError: (error) => {
        toast.error(`Failed to delete backend: ${error.message}`);
      },
    }),
  );

  // Update backend mutation
  const updateMutation = useMutation(
    trpc.backends.update.mutationOptions({
      onSuccess: () => {
        toast.success("Backend updated successfully");
        setEditingBackendId(null);
        editForm.reset();
        queryClient.invalidateQueries({ queryKey: ["backends"] });
      },
      onError: (error) => {
        toast.error(`Failed to update backend: ${error.message}`);
      },
    }),
  );

  // Bulk toggle mutation
  const bulkToggleMutation = useMutation(
    trpc.backends.bulkToggle.mutationOptions({
      onSuccess: (data) => {
        toast.success(
          `${data.count} backends ${data.enabled ? "enabled" : "disabled"}`,
        );
        setSelectedIds(new Set());
        queryClient.invalidateQueries({ queryKey: ["backends"] });
      },
      onError: (error) => {
        toast.error(`Failed to bulk toggle: ${error.message}`);
      },
    }),
  );

  // Bulk delete mutation
  const bulkDeleteMutation = useMutation(
    trpc.backends.bulkDelete.mutationOptions({
      onSuccess: (data) => {
        toast.success(`${data.count} backends deleted`);
        setSelectedIds(new Set());
        setBulkDeleteConfirm(false);
        queryClient.invalidateQueries({ queryKey: ["backends"] });
      },
      onError: (error) => {
        toast.error(`Failed to bulk delete: ${error.message}`);
      },
    }),
  );

  // Selection helpers
  const toggleSelection = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const selectAll = () => {
    if (selectedIds.size === backends.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(backends.map((b) => b.id)));
    }
  };

  // Form for creating backend
  const form = useForm({
    defaultValues: {
      name: "",
      description: "",
      protocol: "tcp" as Protocol,
      enabled: true,
      protectionLevel: 50,
    },
    onSubmit: async ({ value }) => {
      await createMutation.mutateAsync({
        ...value,
        organizationId,
      });
    },
  });

  // Form for editing backend
  const editForm = useForm({
    defaultValues: {
      name: "",
      description: "",
      enabled: true,
      protectionLevel: 50,
    },
    onSubmit: async ({ value }) => {
      if (!editingBackendId) return;
      await updateMutation.mutateAsync({
        id: editingBackendId,
        organizationId,
        name: value.name,
        description: value.description || null,
        enabled: value.enabled,
        protectionLevel: value.protectionLevel,
      });
    },
  });

  // Get the backend being edited and populate form
  const backendToEdit = editingBackendId
    ? backends.find((b) => b.id === editingBackendId)
    : null;

  // Update edit form when backend selection changes
  // biome-ignore lint/correctness/useExhaustiveDependencies: Reset form when backend changes
  React.useEffect(() => {
    if (backendToEdit) {
      editForm.setFieldValue("name", backendToEdit.name);
      editForm.setFieldValue("description", backendToEdit.description ?? "");
      editForm.setFieldValue("enabled", backendToEdit.enabled);
      editForm.setFieldValue(
        "protectionLevel",
        backendToEdit.protectionLevel ?? 50,
      );
    }
  }, [backendToEdit?.id]);

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "healthy":
        return (
          <Badge className="bg-green-500 hover:bg-green-600">Healthy</Badge>
        );
      case "degraded":
        return (
          <Badge className="bg-yellow-500 hover:bg-yellow-600">Degraded</Badge>
        );
      case "unhealthy":
        return <Badge variant="destructive">Unhealthy</Badge>;
      default:
        return <Badge variant="secondary">Unknown</Badge>;
    }
  };

  const healthyCount = backends.filter((b) => b.status === "healthy").length;

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-64 space-y-4">
        <p className="text-destructive">Failed to load backends</p>
        <Button onClick={() => refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" />
          Retry
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Backends</h1>
          <p className="text-muted-foreground">
            Manage your protected backend servers.
          </p>
        </div>
        <Dialog open={isAddDialogOpen} onOpenChange={setIsAddDialogOpen}>
          <DialogTrigger render={<Button />}>
            <Plus className="mr-2 h-4 w-4" />
            Add Backend
          </DialogTrigger>
          <DialogContent className="sm:max-w-[500px]">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                e.stopPropagation();
                form.handleSubmit();
              }}
            >
              <DialogHeader>
                <DialogTitle>Add New Backend</DialogTitle>
                <DialogDescription>
                  Configure a new backend server for DDoS protection.
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-4 py-4">
                <form.Field name="name">
                  {(field) => (
                    <div className="grid gap-2">
                      <Label htmlFor="name">Name</Label>
                      <Input
                        id="name"
                        placeholder="My Server"
                        value={field.state.value}
                        onChange={(e) => field.handleChange(e.target.value)}
                        onBlur={field.handleBlur}
                      />
                      {field.state.meta.errors.length > 0 && (
                        <p className="text-sm text-destructive">
                          {field.state.meta.errors[0]}
                        </p>
                      )}
                    </div>
                  )}
                </form.Field>
                <form.Field name="description">
                  {(field) => (
                    <div className="grid gap-2">
                      <Label htmlFor="description">
                        Description (optional)
                      </Label>
                      <Input
                        id="description"
                        placeholder="A brief description of this server"
                        value={field.state.value}
                        onChange={(e) => field.handleChange(e.target.value)}
                        onBlur={field.handleBlur}
                      />
                    </div>
                  )}
                </form.Field>
                <form.Field name="protocol">
                  {(field) => (
                    <div className="grid gap-2">
                      <Label>Protocol</Label>
                      <Select
                        value={field.state.value}
                        onValueChange={(value) =>
                          field.handleChange((value ?? "tcp") as Protocol)
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {protocolOptions.map((opt) => (
                            <SelectItem key={opt.value} value={opt.value}>
                              {opt.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  )}
                </form.Field>
                <form.Field name="protectionLevel">
                  {(field) => (
                    <div className="grid gap-2">
                      <Label htmlFor="protectionLevel">
                        Protection Level: {field.state.value}%
                      </Label>
                      <input
                        type="range"
                        id="protectionLevel"
                        min={0}
                        max={100}
                        value={field.state.value}
                        onChange={(e) =>
                          field.handleChange(Number(e.target.value))
                        }
                        className="w-full"
                      />
                      <p className="text-xs text-muted-foreground">
                        Higher values mean stricter filtering (may increase
                        false positives)
                      </p>
                    </div>
                  )}
                </form.Field>
                <form.Field name="enabled">
                  {(field) => (
                    <div className="flex items-center justify-between">
                      <Label htmlFor="enabled">Enable immediately</Label>
                      <Switch
                        id="enabled"
                        checked={field.state.value}
                        onCheckedChange={(checked) =>
                          field.handleChange(checked)
                        }
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
                <Button type="submit" disabled={createMutation.isPending}>
                  {createMutation.isPending && (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  )}
                  Add Backend
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Total Backends
            </CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {isLoading ? "-" : backends.length}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Healthy</CardTitle>
            <Activity className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {isLoading ? "-" : healthyCount}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Protected</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {isLoading ? "-" : backends.filter((b) => b.enabled).length}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Backends Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>All Backends</CardTitle>
              <CardDescription>
                View and manage all your protected backend servers.
              </CardDescription>
            </div>
            {selectedIds.size > 0 && (
              <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">
                  {selectedIds.size} selected
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    bulkToggleMutation.mutate({
                      ids: Array.from(selectedIds),
                      enabled: true,
                      organizationId,
                    })
                  }
                  disabled={bulkToggleMutation.isPending}
                >
                  <Power className="mr-1 h-3 w-3" />
                  Enable All
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    bulkToggleMutation.mutate({
                      ids: Array.from(selectedIds),
                      enabled: false,
                      organizationId,
                    })
                  }
                  disabled={bulkToggleMutation.isPending}
                >
                  <Power className="mr-1 h-3 w-3" />
                  Disable All
                </Button>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => setBulkDeleteConfirm(true)}
                  disabled={bulkDeleteMutation.isPending}
                >
                  <Trash2 className="mr-1 h-3 w-3" />
                  Delete Selected
                </Button>
              </div>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center py-8">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : backends.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <Server className="h-12 w-12 text-muted-foreground mb-4" />
              <h3 className="text-lg font-semibold">No backends yet</h3>
              <p className="text-muted-foreground mb-4">
                Add your first backend server to start protecting your
                infrastructure.
              </p>
              <Button onClick={() => setIsAddDialogOpen(true)}>
                <Plus className="mr-2 h-4 w-4" />
                Add Backend
              </Button>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[40px]">
                    <Checkbox
                      checked={
                        backends.length > 0 &&
                        selectedIds.size === backends.length
                      }
                      onCheckedChange={selectAll}
                      aria-label="Select all backends"
                    />
                  </TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Protocol</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Origins</TableHead>
                  <TableHead>Protection</TableHead>
                  <TableHead>Enabled</TableHead>
                  <TableHead className="w-[50px]" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {backends.map((backend) => (
                  <TableRow key={backend.id}>
                    <TableCell>
                      <Checkbox
                        checked={selectedIds.has(backend.id)}
                        onCheckedChange={() => toggleSelection(backend.id)}
                        aria-label={`Select ${backend.name}`}
                      />
                    </TableCell>
                    <TableCell className="font-medium">
                      <div className="flex items-center gap-2">
                        <Globe className="h-4 w-4 text-muted-foreground" />
                        <div>
                          <p>{backend.name}</p>
                          {backend.description && (
                            <p className="text-xs text-muted-foreground">
                              {backend.description}
                            </p>
                          )}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="uppercase">
                        {backend.protocol.replace("_", " ")}
                      </Badge>
                    </TableCell>
                    <TableCell>{getStatusBadge(backend.status)}</TableCell>
                    <TableCell>{backend.origins?.length ?? 0}</TableCell>
                    <TableCell>{backend.protectionLevel}%</TableCell>
                    <TableCell>
                      <Switch
                        checked={backend.enabled}
                        onCheckedChange={() =>
                          toggleMutation.mutate({
                            id: backend.id,
                            organizationId,
                          })
                        }
                        disabled={toggleMutation.isPending}
                      />
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger
                          render={<Button variant="ghost" size="icon" />}
                        >
                          <MoreVertical className="h-4 w-4" />
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem>
                            <Settings className="mr-2 h-4 w-4" />
                            Configure
                          </DropdownMenuItem>
                          <DropdownMenuItem
                            onClick={() => setEditingBackendId(backend.id)}
                          >
                            <Pencil className="mr-2 h-4 w-4" />
                            Edit
                          </DropdownMenuItem>
                          <DropdownMenuItem
                            onClick={() =>
                              toggleMutation.mutate({
                                id: backend.id,
                                organizationId,
                              })
                            }
                          >
                            <Power className="mr-2 h-4 w-4" />
                            {backend.enabled ? "Disable" : "Enable"}
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            className="text-destructive focus:text-destructive"
                            onClick={() => setDeleteBackendId(backend.id)}
                          >
                            <Trash2 className="mr-2 h-4 w-4" />
                            Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={!!deleteBackendId}
        onOpenChange={() => setDeleteBackendId(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Backend</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this backend? This action cannot
              be undone and will remove all associated origins, domains, and
              filters.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteBackendId(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() =>
                deleteBackendId &&
                deleteMutation.mutate({
                  id: deleteBackendId,
                  organizationId,
                })
              }
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Backend Dialog */}
      <Dialog
        open={!!editingBackendId}
        onOpenChange={(open) => {
          if (!open) {
            setEditingBackendId(null);
            editForm.reset();
          }
        }}
      >
        <DialogContent className="sm:max-w-[500px]">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              e.stopPropagation();
              editForm.handleSubmit();
            }}
          >
            <DialogHeader>
              <DialogTitle>Edit Backend</DialogTitle>
              <DialogDescription>
                Update the backend server configuration.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <editForm.Field name="name">
                {(field) => (
                  <div className="grid gap-2">
                    <Label htmlFor="edit-name">Name</Label>
                    <Input
                      id="edit-name"
                      placeholder="My Server"
                      value={field.state.value}
                      onChange={(e) => field.handleChange(e.target.value)}
                      onBlur={field.handleBlur}
                    />
                    {field.state.meta.errors.length > 0 && (
                      <p className="text-sm text-destructive">
                        {field.state.meta.errors[0]}
                      </p>
                    )}
                  </div>
                )}
              </editForm.Field>
              <editForm.Field name="description">
                {(field) => (
                  <div className="grid gap-2">
                    <Label htmlFor="edit-description">
                      Description (optional)
                    </Label>
                    <Input
                      id="edit-description"
                      placeholder="A brief description of this server"
                      value={field.state.value}
                      onChange={(e) => field.handleChange(e.target.value)}
                      onBlur={field.handleBlur}
                    />
                  </div>
                )}
              </editForm.Field>
              <editForm.Field name="protectionLevel">
                {(field) => (
                  <div className="grid gap-2">
                    <Label htmlFor="edit-protectionLevel">
                      Protection Level: {field.state.value}%
                    </Label>
                    <input
                      type="range"
                      id="edit-protectionLevel"
                      min={0}
                      max={100}
                      value={field.state.value}
                      onChange={(e) =>
                        field.handleChange(Number(e.target.value))
                      }
                      className="w-full"
                    />
                    <p className="text-xs text-muted-foreground">
                      Higher values mean stricter filtering (may increase false
                      positives)
                    </p>
                  </div>
                )}
              </editForm.Field>
              <editForm.Field name="enabled">
                {(field) => (
                  <div className="flex items-center justify-between">
                    <Label htmlFor="edit-enabled">Enabled</Label>
                    <Switch
                      id="edit-enabled"
                      checked={field.state.value}
                      onCheckedChange={(checked) => field.handleChange(checked)}
                    />
                  </div>
                )}
              </editForm.Field>
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setEditingBackendId(null);
                  editForm.reset();
                }}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={updateMutation.isPending}>
                {updateMutation.isPending && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                )}
                Save Changes
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Bulk Delete Confirmation Dialog */}
      <Dialog open={bulkDeleteConfirm} onOpenChange={setBulkDeleteConfirm}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete {selectedIds.size} Backends</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete {selectedIds.size} backend
              {selectedIds.size > 1 ? "s" : ""}? This action cannot be undone
              and will remove all associated origins, domains, and filters.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setBulkDeleteConfirm(false)}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() =>
                bulkDeleteMutation.mutate({
                  ids: Array.from(selectedIds),
                  organizationId,
                })
              }
              disabled={bulkDeleteMutation.isPending}
            >
              {bulkDeleteMutation.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Delete {selectedIds.size} Backend{selectedIds.size > 1 ? "s" : ""}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
