import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Plus,
  Filter,
  MoreHorizontal,
  Pencil,
  Trash2,
  Power,
  PowerOff,
  Shield,
  Ban,
  AlertTriangle,
  FileText,
  GripVertical,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Skeleton } from "@/components/ui/skeleton";
import {
  filterRulesQueryOptions,
  useCreateFilterRule,
  useUpdateFilterRule,
  useDeleteFilterRule,
  type FilterRule,
} from "@/lib/api";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

// Mock data
const mockFilterRules: FilterRule[] = [
  {
    id: "1",
    name: "Rate Limit - API Endpoints",
    description: "Limit requests to 100 per minute for API endpoints",
    type: "rate_limit",
    action: "block",
    priority: 1,
    isEnabled: true,
    conditions: [
      { field: "path", operator: "contains", value: "/api/" },
    ],
    rateLimit: { requests: 100, window: 60, burstSize: 10 },
    createdAt: "2024-01-01T00:00:00Z",
    updatedAt: "2024-01-15T00:00:00Z",
  },
  {
    id: "2",
    name: "Block Known Bad IPs",
    description: "Block traffic from known malicious IP ranges",
    type: "ip_block",
    action: "block",
    priority: 2,
    isEnabled: true,
    conditions: [
      { field: "ip", operator: "in", value: ["192.168.1.0/24", "10.0.0.0/8"] },
    ],
    createdAt: "2024-01-02T00:00:00Z",
    updatedAt: "2024-01-14T00:00:00Z",
  },
  {
    id: "3",
    name: "Geo Block - Sanctioned Countries",
    description: "Block traffic from sanctioned countries",
    type: "geo_block",
    action: "block",
    priority: 3,
    isEnabled: true,
    conditions: [
      { field: "country", operator: "in", value: ["NK", "IR", "SY"] },
    ],
    createdAt: "2024-01-03T00:00:00Z",
    updatedAt: "2024-01-13T00:00:00Z",
  },
  {
    id: "4",
    name: "Challenge Suspicious User Agents",
    description: "Challenge requests with suspicious user agent strings",
    type: "header_filter",
    action: "challenge",
    priority: 4,
    isEnabled: true,
    conditions: [
      { field: "user-agent", operator: "regex", value: ".*bot.*|.*crawler.*|.*spider.*" },
    ],
    createdAt: "2024-01-04T00:00:00Z",
    updatedAt: "2024-01-12T00:00:00Z",
  },
  {
    id: "5",
    name: "Log Admin Access",
    description: "Log all access to admin endpoints",
    type: "path_filter",
    action: "log",
    priority: 5,
    isEnabled: false,
    conditions: [
      { field: "path", operator: "contains", value: "/admin" },
    ],
    createdAt: "2024-01-05T00:00:00Z",
    updatedAt: "2024-01-11T00:00:00Z",
  },
];

interface FilterFormData {
  name: string;
  description: string;
  type: FilterRule["type"];
  action: FilterRule["action"];
  priority: number;
  isEnabled: boolean;
  conditionField: string;
  conditionOperator: string;
  conditionValue: string;
  rateLimitRequests?: number;
  rateLimitWindow?: number;
}

const defaultFormData: FilterFormData = {
  name: "",
  description: "",
  type: "rate_limit",
  action: "block",
  priority: 1,
  isEnabled: true,
  conditionField: "path",
  conditionOperator: "contains",
  conditionValue: "",
  rateLimitRequests: 100,
  rateLimitWindow: 60,
};

const typeIcons = {
  rate_limit: AlertTriangle,
  ip_block: Ban,
  geo_block: Shield,
  header_filter: FileText,
  path_filter: Filter,
  custom: FileText,
};

const actionColors = {
  block: "destructive" as const,
  allow: "success" as const,
  challenge: "warning" as const,
  log: "secondary" as const,
};

export function Filters() {
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false);
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false);
  const [selectedRule, setSelectedRule] = useState<FilterRule | null>(null);
  const [formData, setFormData] = useState<FilterFormData>(defaultFormData);

  const { data: filterRules, isLoading } = useQuery({
    ...filterRulesQueryOptions(),
    placeholderData: mockFilterRules,
  });

  const createFilterRule = useCreateFilterRule();
  const updateFilterRule = useUpdateFilterRule();
  const deleteFilterRule = useDeleteFilterRule();

  const handleCreate = async () => {
    try {
      await createFilterRule.mutateAsync({
        name: formData.name,
        description: formData.description,
        type: formData.type,
        action: formData.action,
        priority: formData.priority,
        isEnabled: formData.isEnabled,
        conditions: [
          {
            field: formData.conditionField,
            operator: formData.conditionOperator as FilterRule["conditions"][0]["operator"],
            value: formData.conditionValue,
          },
        ],
        rateLimit:
          formData.type === "rate_limit"
            ? {
                requests: formData.rateLimitRequests || 100,
                window: formData.rateLimitWindow || 60,
              }
            : undefined,
      });
      toast.success("Filter rule created successfully");
      setIsCreateDialogOpen(false);
      setFormData(defaultFormData);
    } catch {
      toast.error("Failed to create filter rule");
    }
  };

  const handleUpdate = async () => {
    if (!selectedRule) return;
    try {
      await updateFilterRule.mutateAsync({
        id: selectedRule.id,
        name: formData.name,
        description: formData.description,
        type: formData.type,
        action: formData.action,
        priority: formData.priority,
        isEnabled: formData.isEnabled,
        conditions: [
          {
            field: formData.conditionField,
            operator: formData.conditionOperator as FilterRule["conditions"][0]["operator"],
            value: formData.conditionValue,
          },
        ],
        rateLimit:
          formData.type === "rate_limit"
            ? {
                requests: formData.rateLimitRequests || 100,
                window: formData.rateLimitWindow || 60,
              }
            : undefined,
      });
      toast.success("Filter rule updated successfully");
      setIsEditDialogOpen(false);
      setSelectedRule(null);
      setFormData(defaultFormData);
    } catch {
      toast.error("Failed to update filter rule");
    }
  };

  const handleDelete = async () => {
    if (!selectedRule) return;
    try {
      await deleteFilterRule.mutateAsync(selectedRule.id);
      toast.success("Filter rule deleted successfully");
      setIsDeleteDialogOpen(false);
      setSelectedRule(null);
    } catch {
      toast.error("Failed to delete filter rule");
    }
  };

  const handleToggleEnabled = async (rule: FilterRule) => {
    try {
      await updateFilterRule.mutateAsync({
        id: rule.id,
        isEnabled: !rule.isEnabled,
      });
      toast.success(
        `Filter rule ${rule.isEnabled ? "disabled" : "enabled"} successfully`
      );
    } catch {
      toast.error("Failed to update filter rule status");
    }
  };

  const openEditDialog = (rule: FilterRule) => {
    setSelectedRule(rule);
    setFormData({
      name: rule.name,
      description: rule.description,
      type: rule.type,
      action: rule.action,
      priority: rule.priority,
      isEnabled: rule.isEnabled,
      conditionField: rule.conditions[0]?.field || "path",
      conditionOperator: rule.conditions[0]?.operator || "contains",
      conditionValue: String(rule.conditions[0]?.value || ""),
      rateLimitRequests: rule.rateLimit?.requests,
      rateLimitWindow: rule.rateLimit?.window,
    });
    setIsEditDialogOpen(true);
  };

  const openDeleteDialog = (rule: FilterRule) => {
    setSelectedRule(rule);
    setIsDeleteDialogOpen(true);
  };

  const sortedRules = [...(filterRules || [])].sort(
    (a, b) => a.priority - b.priority
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Filter Rules</h1>
          <p className="text-muted-foreground">
            Configure traffic filtering and protection rules
          </p>
        </div>
        <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Add Rule
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-[600px]">
            <DialogHeader>
              <DialogTitle>Create Filter Rule</DialogTitle>
              <DialogDescription>
                Define a new traffic filtering rule
              </DialogDescription>
            </DialogHeader>
            <FilterForm formData={formData} setFormData={setFormData} />
            <DialogFooter>
              <Button
                variant="outline"
                onClick={() => setIsCreateDialogOpen(false)}
              >
                Cancel
              </Button>
              <Button
                onClick={handleCreate}
                disabled={createFilterRule.isPending}
              >
                {createFilterRule.isPending ? "Creating..." : "Create Rule"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Rules</CardTitle>
            <Filter className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{filterRules?.length || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Rules</CardTitle>
            <Power className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {filterRules?.filter((r) => r.isEnabled).length || 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Blocking Rules</CardTitle>
            <Ban className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {filterRules?.filter((r) => r.action === "block").length || 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Rate Limiters</CardTitle>
            <AlertTriangle className="h-4 w-4 text-yellow-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {filterRules?.filter((r) => r.type === "rate_limit").length || 0}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filter Rules List */}
      <Card>
        <CardHeader>
          <CardTitle>Active Rules</CardTitle>
          <CardDescription>
            Rules are processed in order of priority (lowest number first)
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-4">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-24 w-full" />
              ))}
            </div>
          ) : (
            <div className="space-y-3">
              {sortedRules.map((rule) => {
                const Icon = typeIcons[rule.type];
                return (
                  <div
                    key={rule.id}
                    className={cn(
                      "flex items-start gap-4 rounded-lg border p-4 transition-colors",
                      !rule.isEnabled && "opacity-50"
                    )}
                  >
                    <div className="flex items-center gap-2">
                      <GripVertical className="h-5 w-5 cursor-grab text-muted-foreground" />
                      <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-muted">
                        <Icon className="h-5 w-5" />
                      </div>
                    </div>
                    <div className="flex-1 space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{rule.name}</span>
                        <Badge variant="outline" className="text-xs">
                          Priority: {rule.priority}
                        </Badge>
                        <Badge variant={actionColors[rule.action]}>
                          {rule.action}
                        </Badge>
                        {!rule.isEnabled && (
                          <Badge variant="secondary">Disabled</Badge>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground">
                        {rule.description}
                      </p>
                      <div className="flex flex-wrap gap-2 pt-1">
                        {rule.conditions.map((condition, index) => (
                          <Badge key={index} variant="outline" className="font-mono text-xs">
                            {condition.field} {condition.operator}{" "}
                            {Array.isArray(condition.value)
                              ? condition.value.join(", ")
                              : condition.value}
                          </Badge>
                        ))}
                        {rule.rateLimit && (
                          <Badge variant="outline" className="font-mono text-xs">
                            {rule.rateLimit.requests} req / {rule.rateLimit.window}s
                          </Badge>
                        )}
                      </div>
                    </div>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => openEditDialog(rule)}>
                          <Pencil className="mr-2 h-4 w-4" />
                          Edit
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => handleToggleEnabled(rule)}
                        >
                          {rule.isEnabled ? (
                            <>
                              <PowerOff className="mr-2 h-4 w-4" />
                              Disable
                            </>
                          ) : (
                            <>
                              <Power className="mr-2 h-4 w-4" />
                              Enable
                            </>
                          )}
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          className="text-destructive"
                          onClick={() => openDeleteDialog(rule)}
                        >
                          <Trash2 className="mr-2 h-4 w-4" />
                          Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Edit Dialog */}
      <Dialog open={isEditDialogOpen} onOpenChange={setIsEditDialogOpen}>
        <DialogContent className="sm:max-w-[600px]">
          <DialogHeader>
            <DialogTitle>Edit Filter Rule</DialogTitle>
            <DialogDescription>
              Update the configuration for {selectedRule?.name}
            </DialogDescription>
          </DialogHeader>
          <FilterForm formData={formData} setFormData={setFormData} />
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsEditDialogOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleUpdate}
              disabled={updateFilterRule.isPending}
            >
              {updateFilterRule.isPending ? "Saving..." : "Save Changes"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <AlertDialog
        open={isDeleteDialogOpen}
        onOpenChange={setIsDeleteDialogOpen}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Filter Rule</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{selectedRule?.name}"? This action
              cannot be undone and may affect your traffic protection.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteFilterRule.isPending ? "Deleting..." : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

interface FilterFormProps {
  formData: FilterFormData;
  setFormData: React.Dispatch<React.SetStateAction<FilterFormData>>;
}

function FilterForm({ formData, setFormData }: FilterFormProps) {
  return (
    <div className="grid gap-4 py-4">
      <div className="grid gap-2">
        <Label htmlFor="name">Rule Name</Label>
        <Input
          id="name"
          placeholder="My Filter Rule"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
        />
      </div>
      <div className="grid gap-2">
        <Label htmlFor="description">Description</Label>
        <Textarea
          id="description"
          placeholder="What does this rule do?"
          value={formData.description}
          onChange={(e) =>
            setFormData({ ...formData, description: e.target.value })
          }
        />
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="grid gap-2">
          <Label htmlFor="type">Rule Type</Label>
          <Select
            value={formData.type}
            onValueChange={(value: FilterRule["type"]) =>
              setFormData({ ...formData, type: value })
            }
          >
            <SelectTrigger>
              <SelectValue placeholder="Select type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="rate_limit">Rate Limit</SelectItem>
              <SelectItem value="ip_block">IP Block</SelectItem>
              <SelectItem value="geo_block">Geo Block</SelectItem>
              <SelectItem value="header_filter">Header Filter</SelectItem>
              <SelectItem value="path_filter">Path Filter</SelectItem>
              <SelectItem value="custom">Custom</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="action">Action</Label>
          <Select
            value={formData.action}
            onValueChange={(value: FilterRule["action"]) =>
              setFormData({ ...formData, action: value })
            }
          >
            <SelectTrigger>
              <SelectValue placeholder="Select action" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="block">Block</SelectItem>
              <SelectItem value="allow">Allow</SelectItem>
              <SelectItem value="challenge">Challenge</SelectItem>
              <SelectItem value="log">Log Only</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>
      <div className="grid gap-2">
        <Label htmlFor="priority">Priority</Label>
        <Input
          id="priority"
          type="number"
          min="1"
          value={formData.priority}
          onChange={(e) =>
            setFormData({ ...formData, priority: parseInt(e.target.value) || 1 })
          }
        />
        <p className="text-xs text-muted-foreground">
          Lower numbers are processed first
        </p>
      </div>

      {/* Condition Fields */}
      <div className="space-y-2">
        <Label>Condition</Label>
        <div className="grid grid-cols-3 gap-2">
          <Select
            value={formData.conditionField}
            onValueChange={(value) =>
              setFormData({ ...formData, conditionField: value })
            }
          >
            <SelectTrigger>
              <SelectValue placeholder="Field" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="path">Path</SelectItem>
              <SelectItem value="ip">IP Address</SelectItem>
              <SelectItem value="country">Country</SelectItem>
              <SelectItem value="user-agent">User Agent</SelectItem>
              <SelectItem value="referer">Referer</SelectItem>
              <SelectItem value="host">Host</SelectItem>
            </SelectContent>
          </Select>
          <Select
            value={formData.conditionOperator}
            onValueChange={(value) =>
              setFormData({ ...formData, conditionOperator: value })
            }
          >
            <SelectTrigger>
              <SelectValue placeholder="Operator" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="equals">Equals</SelectItem>
              <SelectItem value="contains">Contains</SelectItem>
              <SelectItem value="regex">Regex</SelectItem>
              <SelectItem value="in">In List</SelectItem>
              <SelectItem value="gt">Greater Than</SelectItem>
              <SelectItem value="lt">Less Than</SelectItem>
            </SelectContent>
          </Select>
          <Input
            placeholder="Value"
            value={formData.conditionValue}
            onChange={(e) =>
              setFormData({ ...formData, conditionValue: e.target.value })
            }
          />
        </div>
      </div>

      {/* Rate Limit Fields */}
      {formData.type === "rate_limit" && (
        <div className="grid grid-cols-2 gap-4">
          <div className="grid gap-2">
            <Label htmlFor="rateLimitRequests">Requests</Label>
            <Input
              id="rateLimitRequests"
              type="number"
              min="1"
              value={formData.rateLimitRequests}
              onChange={(e) =>
                setFormData({
                  ...formData,
                  rateLimitRequests: parseInt(e.target.value) || 100,
                })
              }
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="rateLimitWindow">Window (seconds)</Label>
            <Input
              id="rateLimitWindow"
              type="number"
              min="1"
              value={formData.rateLimitWindow}
              onChange={(e) =>
                setFormData({
                  ...formData,
                  rateLimitWindow: parseInt(e.target.value) || 60,
                })
              }
            />
          </div>
        </div>
      )}

      <div className="flex items-center justify-between">
        <Label htmlFor="isEnabled">Enabled</Label>
        <Switch
          id="isEnabled"
          checked={formData.isEnabled}
          onCheckedChange={(checked) =>
            setFormData({ ...formData, isEnabled: checked })
          }
        />
      </div>
    </div>
  );
}
