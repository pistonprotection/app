import { useForm } from "@tanstack/react-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import {
  Copy,
  Filter,
  Globe,
  Loader2,
  MoreVertical,
  Pencil,
  Plus,
  Server,
  Shield,
  Trash2,
  Zap,
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { useTRPC } from "@/lib/trpc/client";

export const Route = createFileRoute("/dashboard/filters")({
  component: FiltersPage,
});

const filterTypes = [
  "tcp",
  "udp",
  "http",
  "quic",
  "minecraft_java",
  "minecraft_bedrock",
] as const;

type FilterType = (typeof filterTypes)[number];
type FilterAction = "allow" | "block" | "rate_limit" | "challenge";

const filterSchema = z.object({
  name: z.string().min(1, "Name is required"),
  type: z.enum(filterTypes),
  action: z.enum(["allow", "block", "rate_limit", "challenge"]),
  priority: z.number().min(0).max(1000),
  enabled: z.boolean(),
  conditions: z.string().optional(),
  rateLimit: z.number().optional(),
  rateLimitWindow: z.number().optional(),
});

function FiltersPage() {
  const [isAddDialogOpen, setIsAddDialogOpen] = useState(false);
  const [editingFilter, setEditingFilter] = useState<string | null>(null);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"all" | FilterType>("all");

  const trpc = useTRPC();
  const queryClient = useQueryClient();

  // Get filters
  const { data: filtersData, isLoading } = useQuery(
    trpc.filters.list.queryOptions({
      type: activeTab === "all" ? undefined : activeTab,
    }),
  );

  // Get filter stats
  const { data: filterStats } = useQuery(trpc.filters.getStats.queryOptions());

  // Create filter mutation
  const createMutation = useMutation(
    trpc.filters.create.mutationOptions({
      onSuccess: () => {
        toast.success("Filter created successfully");
        setIsAddDialogOpen(false);
        form.reset();
        queryClient.invalidateQueries({ queryKey: ["filters"] });
      },
      onError: (error) => {
        toast.error(`Failed to create filter: ${error.message}`);
      },
    }),
  );

  // Update filter mutation
  const updateMutation = useMutation(
    trpc.filters.update.mutationOptions({
      onSuccess: () => {
        toast.success("Filter updated");
        setEditingFilter(null);
        editForm.reset();
        queryClient.invalidateQueries({ queryKey: ["filters"] });
      },
      onError: (error) => {
        toast.error(`Failed to update filter: ${error.message}`);
      },
    }),
  );

  // Delete filter mutation
  const deleteMutation = useMutation(
    trpc.filters.delete.mutationOptions({
      onSuccess: () => {
        toast.success("Filter deleted");
        setDeleteId(null);
        queryClient.invalidateQueries({ queryKey: ["filters"] });
      },
      onError: (error) => {
        toast.error(`Failed to delete filter: ${error.message}`);
      },
    }),
  );

  // Toggle filter enabled
  const toggleMutation = useMutation(
    trpc.filters.toggle.mutationOptions({
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: ["filters"] });
      },
      onError: (error) => {
        toast.error(`Failed to toggle filter: ${error.message}`);
      },
    }),
  );

  // Duplicate filter mutation
  const duplicateMutation = useMutation(
    trpc.filters.duplicate.mutationOptions({
      onSuccess: () => {
        toast.success("Filter duplicated");
        queryClient.invalidateQueries({ queryKey: ["filters"] });
      },
      onError: (error) => {
        toast.error(`Failed to duplicate filter: ${error.message}`);
      },
    }),
  );

  // Form for creating filters
  const form = useForm({
    defaultValues: {
      name: "",
      type: "tcp" as FilterType,
      action: "block" as FilterAction,
      priority: 100,
      enabled: true,
      conditions: "",
      rateLimit: 1000,
      rateLimitWindow: 60,
    },
    onSubmit: async ({ value }) => {
      await createMutation.mutateAsync({
        name: value.name,
        type: value.type,
        action: value.action,
        priority: value.priority,
        enabled: value.enabled,
        conditions: value.conditions || undefined,
        rateLimit: value.action === "rate_limit" ? value.rateLimit : undefined,
        rateLimitWindow:
          value.action === "rate_limit" ? value.rateLimitWindow : undefined,
      });
    },
    validators: {
      onChange: filterSchema,
    },
  });

  // Form for editing filters
  const editForm = useForm({
    defaultValues: {
      name: "",
      type: "tcp" as FilterType,
      action: "block" as FilterAction,
      priority: 100,
      enabled: true,
      conditions: "",
      rateLimit: 1000,
      rateLimitWindow: 60,
    },
    onSubmit: async ({ value }) => {
      if (!editingFilter) return;
      await updateMutation.mutateAsync({
        id: editingFilter,
        name: value.name,
        type: value.type,
        action: value.action,
        priority: value.priority,
        enabled: value.enabled,
        conditions: value.conditions || undefined,
        rateLimit: value.action === "rate_limit" ? value.rateLimit : undefined,
        rateLimitWindow:
          value.action === "rate_limit" ? value.rateLimitWindow : undefined,
      });
    },
    validators: {
      onChange: filterSchema,
    },
  });

  const getActionBadge = (action: string) => {
    switch (action) {
      case "allow":
        return <Badge className="bg-green-500">Allow</Badge>;
      case "block":
        return <Badge variant="destructive">Block</Badge>;
      case "rate_limit":
        return <Badge className="bg-yellow-500">Rate Limit</Badge>;
      case "challenge":
        return <Badge className="bg-blue-500">Challenge</Badge>;
      default:
        return <Badge>{action}</Badge>;
    }
  };

  const filters = filtersData?.items ?? [];

  // Get the filter being edited and populate form
  const filterToEdit = editingFilter
    ? filters.find((f) => f.id === editingFilter)
    : null;

  // Update edit form when filter selection changes
  // biome-ignore lint/correctness/useExhaustiveDependencies: Reset form when filter changes
  React.useEffect(() => {
    if (filterToEdit) {
      editForm.setFieldValue("name", filterToEdit.name);
      editForm.setFieldValue("type", filterToEdit.type as FilterType);
      editForm.setFieldValue("action", filterToEdit.action as FilterAction);
      editForm.setFieldValue("priority", filterToEdit.priority);
      editForm.setFieldValue("enabled", filterToEdit.enabled);
      editForm.setFieldValue("conditions", filterToEdit.conditions ?? "");
    }
  }, [filterToEdit?.id]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Filters</h1>
          <p className="text-muted-foreground">
            Configure DDoS protection filter rules.
          </p>
        </div>
        <Dialog open={isAddDialogOpen} onOpenChange={setIsAddDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Add Filter
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-[600px]">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                form.handleSubmit();
              }}
            >
              <DialogHeader>
                <DialogTitle>Add New Filter Rule</DialogTitle>
                <DialogDescription>
                  Create a new filter rule to protect your backends.
                </DialogDescription>
              </DialogHeader>
              <div className="grid gap-4 py-4">
                <form.Field name="name">
                  {(field) => (
                    <div className="grid gap-2">
                      <Label>Rule Name</Label>
                      <Input
                        placeholder="Block SYN Flood"
                        value={field.state.value}
                        onChange={(e) => field.handleChange(e.target.value)}
                      />
                      {field.state.meta.errors.length > 0 && (
                        <p className="text-sm text-destructive">
                          {field.state.meta.errors[0]}
                        </p>
                      )}
                    </div>
                  )}
                </form.Field>
                <div className="grid grid-cols-2 gap-4">
                  <form.Field name="type">
                    {(field) => (
                      <div className="grid gap-2">
                        <Label>Type</Label>
                        <Select
                          value={field.state.value}
                          onValueChange={(v) =>
                            field.handleChange(v as FilterType)
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="tcp">TCP</SelectItem>
                            <SelectItem value="udp">UDP</SelectItem>
                            <SelectItem value="http">HTTP</SelectItem>
                            <SelectItem value="quic">QUIC</SelectItem>
                            <SelectItem value="minecraft_java">
                              Minecraft Java
                            </SelectItem>
                            <SelectItem value="minecraft_bedrock">
                              Minecraft Bedrock
                            </SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    )}
                  </form.Field>
                  <form.Field name="action">
                    {(field) => (
                      <div className="grid gap-2">
                        <Label>Action</Label>
                        <Select
                          value={field.state.value}
                          onValueChange={(v) =>
                            field.handleChange(v as FilterAction)
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="allow">Allow</SelectItem>
                            <SelectItem value="block">Block</SelectItem>
                            <SelectItem value="rate_limit">
                              Rate Limit
                            </SelectItem>
                            <SelectItem value="challenge">Challenge</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    )}
                  </form.Field>
                </div>
                <form.Field name="priority">
                  {(field) => (
                    <div className="grid gap-2">
                      <Label htmlFor="filter-priority">
                        Priority (0-1000, higher = processed first)
                      </Label>
                      <Input
                        id="filter-priority"
                        type="number"
                        min={0}
                        max={1000}
                        value={field.state.value}
                        onChange={(e) =>
                          field.handleChange(Number(e.target.value))
                        }
                        aria-describedby="priority-description"
                      />
                      <p id="priority-description" className="sr-only">
                        Filter rules with higher priority values are processed
                        first
                      </p>
                    </div>
                  )}
                </form.Field>
                <form.Field name="conditions">
                  {(field) => (
                    <div className="grid gap-2">
                      <Label>Conditions (JSON expression)</Label>
                      <Textarea
                        placeholder='{"source_ip": {"not_in": ["10.0.0.0/8"]}}'
                        rows={3}
                        value={field.state.value}
                        onChange={(e) => field.handleChange(e.target.value)}
                      />
                      <p className="text-xs text-muted-foreground">
                        Use JSON to define match conditions. See documentation
                        for syntax.
                      </p>
                    </div>
                  )}
                </form.Field>
                <form.Subscribe selector={(state) => state.values.action}>
                  {(action) =>
                    action === "rate_limit" && (
                      <div className="grid grid-cols-2 gap-4">
                        <form.Field name="rateLimit">
                          {(field) => (
                            <div className="grid gap-2">
                              <Label>Rate Limit (requests)</Label>
                              <Input
                                type="number"
                                min={1}
                                value={field.state.value}
                                onChange={(e) =>
                                  field.handleChange(Number(e.target.value))
                                }
                              />
                            </div>
                          )}
                        </form.Field>
                        <form.Field name="rateLimitWindow">
                          {(field) => (
                            <div className="grid gap-2">
                              <Label>Window (seconds)</Label>
                              <Input
                                type="number"
                                min={1}
                                value={field.state.value}
                                onChange={(e) =>
                                  field.handleChange(Number(e.target.value))
                                }
                              />
                            </div>
                          )}
                        </form.Field>
                      </div>
                    )
                  }
                </form.Subscribe>
                <form.Field name="enabled">
                  {(field) => (
                    <div className="flex items-center space-x-2">
                      <Switch
                        checked={field.state.value}
                        onCheckedChange={field.handleChange}
                      />
                      <Label>Enable immediately</Label>
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
                  Create Filter
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Filters</CardTitle>
            <Filter className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {filterStats?.totalFilters ?? 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active</CardTitle>
            <Shield className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {filterStats?.activeFilters ?? 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Hits</CardTitle>
            <Zap className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {formatNumber(filterStats?.totalHits ?? 0)}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Block Rules</CardTitle>
            <Server className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {filterStats?.blockRules ?? 0}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters Table */}
      <Card>
        <CardHeader>
          <CardTitle>Filter Rules</CardTitle>
          <CardDescription>
            Manage your protection filter rules by protocol type.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs
            value={activeTab}
            onValueChange={(v) => setActiveTab(v as typeof activeTab)}
          >
            <TabsList>
              <TabsTrigger value="all">
                <Globe className="mr-2 h-4 w-4" />
                All
              </TabsTrigger>
              <TabsTrigger value="tcp">TCP</TabsTrigger>
              <TabsTrigger value="udp">UDP</TabsTrigger>
              <TabsTrigger value="http">HTTP</TabsTrigger>
              <TabsTrigger value="quic">QUIC</TabsTrigger>
              <TabsTrigger value="minecraft_java">MC Java</TabsTrigger>
              <TabsTrigger value="minecraft_bedrock">MC Bedrock</TabsTrigger>
            </TabsList>
            <TabsContent value={activeTab} className="mt-4">
              {isLoading ? (
                <div className="flex justify-center py-8">
                  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                </div>
              ) : filters.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-8 text-center">
                  <Filter className="h-12 w-12 text-muted-foreground mb-4" />
                  <h3 className="text-lg font-semibold">No filters</h3>
                  <p className="text-muted-foreground">
                    Create your first filter to start protecting your backends.
                  </p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[50px]">Active</TableHead>
                      <TableHead>Name</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Action</TableHead>
                      <TableHead>Priority</TableHead>
                      <TableHead>Conditions</TableHead>
                      <TableHead className="text-right">Hits</TableHead>
                      <TableHead className="w-[50px]" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filters.map((filter) => (
                      <TableRow key={filter.id}>
                        <TableCell>
                          <Switch
                            checked={filter.enabled}
                            onCheckedChange={() =>
                              toggleMutation.mutate({
                                id: filter.id,
                                enabled: !filter.enabled,
                              })
                            }
                          />
                        </TableCell>
                        <TableCell className="font-medium">
                          {filter.name}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">
                            {filter.type.toUpperCase()}
                          </Badge>
                        </TableCell>
                        <TableCell>{getActionBadge(filter.action)}</TableCell>
                        <TableCell>{filter.priority}</TableCell>
                        <TableCell className="max-w-[200px] truncate text-muted-foreground">
                          {filter.conditions || "-"}
                        </TableCell>
                        <TableCell className="text-right">
                          {filter.hits?.toLocaleString() ?? 0}
                        </TableCell>
                        <TableCell>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button
                                variant="ghost"
                                size="icon"
                                aria-label={`Actions for filter ${filter.name}`}
                              >
                                <MoreVertical className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem
                                onClick={() => setEditingFilter(filter.id)}
                              >
                                <Pencil className="mr-2 h-4 w-4" />
                                Edit
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                onClick={() =>
                                  duplicateMutation.mutate({ id: filter.id })
                                }
                              >
                                <Copy className="mr-2 h-4 w-4" />
                                Duplicate
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem
                                onClick={() => setDeleteId(filter.id)}
                                className="text-destructive focus:text-destructive"
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
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* Delete Confirmation Dialog */}
      <Dialog open={!!deleteId} onOpenChange={() => setDeleteId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Filter</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this filter? This action cannot be
              undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteId(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() =>
                deleteId && deleteMutation.mutate({ id: deleteId })
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

      {/* Edit Filter Dialog */}
      <Dialog
        open={!!editingFilter}
        onOpenChange={(open) => {
          if (!open) {
            setEditingFilter(null);
            editForm.reset();
          }
        }}
      >
        <DialogContent className="sm:max-w-[600px]">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              editForm.handleSubmit();
            }}
          >
            <DialogHeader>
              <DialogTitle>Edit Filter Rule</DialogTitle>
              <DialogDescription>
                Update this filter rule&apos;s configuration.
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <editForm.Field name="name">
                {(field) => (
                  <div className="grid gap-2">
                    <Label>Rule Name</Label>
                    <Input
                      placeholder="Block SYN Flood"
                      value={field.state.value}
                      onChange={(e) => field.handleChange(e.target.value)}
                    />
                    {field.state.meta.errors.length > 0 && (
                      <p className="text-sm text-destructive">
                        {field.state.meta.errors[0]}
                      </p>
                    )}
                  </div>
                )}
              </editForm.Field>
              <div className="grid grid-cols-2 gap-4">
                <editForm.Field name="type">
                  {(field) => (
                    <div className="grid gap-2">
                      <Label>Type</Label>
                      <Select
                        value={field.state.value}
                        onValueChange={(v) =>
                          field.handleChange(v as FilterType)
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="tcp">TCP</SelectItem>
                          <SelectItem value="udp">UDP</SelectItem>
                          <SelectItem value="http">HTTP</SelectItem>
                          <SelectItem value="quic">QUIC</SelectItem>
                          <SelectItem value="minecraft_java">
                            Minecraft Java
                          </SelectItem>
                          <SelectItem value="minecraft_bedrock">
                            Minecraft Bedrock
                          </SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  )}
                </editForm.Field>
                <editForm.Field name="action">
                  {(field) => (
                    <div className="grid gap-2">
                      <Label>Action</Label>
                      <Select
                        value={field.state.value}
                        onValueChange={(v) =>
                          field.handleChange(v as FilterAction)
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="allow">Allow</SelectItem>
                          <SelectItem value="block">Block</SelectItem>
                          <SelectItem value="rate_limit">Rate Limit</SelectItem>
                          <SelectItem value="challenge">Challenge</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  )}
                </editForm.Field>
              </div>
              <editForm.Field name="priority">
                {(field) => (
                  <div className="grid gap-2">
                    <Label htmlFor="edit-filter-priority">
                      Priority (0-1000, higher = processed first)
                    </Label>
                    <Input
                      id="edit-filter-priority"
                      type="number"
                      min={0}
                      max={1000}
                      value={field.state.value}
                      onChange={(e) =>
                        field.handleChange(Number(e.target.value))
                      }
                      aria-describedby="edit-priority-description"
                    />
                    <p id="edit-priority-description" className="sr-only">
                      Filter rules with higher priority values are processed
                      first
                    </p>
                  </div>
                )}
              </editForm.Field>
              <editForm.Field name="conditions">
                {(field) => (
                  <div className="grid gap-2">
                    <Label>Conditions (JSON expression)</Label>
                    <Textarea
                      placeholder='{"source_ip": {"not_in": ["10.0.0.0/8"]}}'
                      rows={3}
                      value={field.state.value}
                      onChange={(e) => field.handleChange(e.target.value)}
                    />
                    <p className="text-xs text-muted-foreground">
                      Use JSON to define match conditions. See documentation for
                      syntax.
                    </p>
                  </div>
                )}
              </editForm.Field>
              <editForm.Subscribe selector={(state) => state.values.action}>
                {(action) =>
                  action === "rate_limit" && (
                    <div className="grid grid-cols-2 gap-4">
                      <editForm.Field name="rateLimit">
                        {(field) => (
                          <div className="grid gap-2">
                            <Label>Rate Limit (requests)</Label>
                            <Input
                              type="number"
                              min={1}
                              value={field.state.value}
                              onChange={(e) =>
                                field.handleChange(Number(e.target.value))
                              }
                            />
                          </div>
                        )}
                      </editForm.Field>
                      <editForm.Field name="rateLimitWindow">
                        {(field) => (
                          <div className="grid gap-2">
                            <Label>Window (seconds)</Label>
                            <Input
                              type="number"
                              min={1}
                              value={field.state.value}
                              onChange={(e) =>
                                field.handleChange(Number(e.target.value))
                              }
                            />
                          </div>
                        )}
                      </editForm.Field>
                    </div>
                  )
                }
              </editForm.Subscribe>
              <editForm.Field name="enabled">
                {(field) => (
                  <div className="flex items-center space-x-2">
                    <Switch
                      checked={field.state.value}
                      onCheckedChange={field.handleChange}
                    />
                    <Label>Enabled</Label>
                  </div>
                )}
              </editForm.Field>
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setEditingFilter(null);
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
    </div>
  );
}

function formatNumber(num: number): string {
  if (num >= 1_000_000) return `${(num / 1_000_000).toFixed(1)}M`;
  if (num >= 1_000) return `${(num / 1_000).toFixed(1)}K`;
  return num.toString();
}
