import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Plus,
  Server,
  MoreHorizontal,
  Pencil,
  Trash2,
  Power,
  PowerOff,
  RefreshCw,
  ExternalLink,
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
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
  backendsQueryOptions,
  useCreateBackend,
  useUpdateBackend,
  useDeleteBackend,
  type Backend,
} from "@/lib/api";
import { toast } from "sonner";

// Mock data
const mockBackends: Backend[] = [
  {
    id: "1",
    name: "Primary API Server",
    host: "api-primary.example.com",
    port: 443,
    protocol: "https",
    healthCheckPath: "/health",
    healthCheckInterval: 30,
    weight: 100,
    isActive: true,
    createdAt: "2024-01-01T00:00:00Z",
    updatedAt: "2024-01-15T00:00:00Z",
  },
  {
    id: "2",
    name: "Secondary API Server",
    host: "api-secondary.example.com",
    port: 443,
    protocol: "https",
    healthCheckPath: "/health",
    healthCheckInterval: 30,
    weight: 50,
    isActive: true,
    createdAt: "2024-01-02T00:00:00Z",
    updatedAt: "2024-01-14T00:00:00Z",
  },
  {
    id: "3",
    name: "Static Assets CDN",
    host: "cdn.example.com",
    port: 443,
    protocol: "https",
    healthCheckPath: "/",
    healthCheckInterval: 60,
    weight: 100,
    isActive: true,
    createdAt: "2024-01-03T00:00:00Z",
    updatedAt: "2024-01-13T00:00:00Z",
  },
  {
    id: "4",
    name: "Legacy API (Deprecated)",
    host: "legacy-api.example.com",
    port: 8080,
    protocol: "http",
    healthCheckPath: "/ping",
    healthCheckInterval: 120,
    weight: 10,
    isActive: false,
    createdAt: "2024-01-04T00:00:00Z",
    updatedAt: "2024-01-12T00:00:00Z",
  },
];

interface BackendFormData {
  name: string;
  host: string;
  port: number;
  protocol: "http" | "https";
  healthCheckPath: string;
  healthCheckInterval: number;
  weight: number;
  isActive: boolean;
}

const defaultFormData: BackendFormData = {
  name: "",
  host: "",
  port: 443,
  protocol: "https",
  healthCheckPath: "/health",
  healthCheckInterval: 30,
  weight: 100,
  isActive: true,
};

export function Backends() {
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false);
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false);
  const [selectedBackend, setSelectedBackend] = useState<Backend | null>(null);
  const [formData, setFormData] = useState<BackendFormData>(defaultFormData);

  const { data: backends, isLoading } = useQuery({
    ...backendsQueryOptions(),
    placeholderData: mockBackends,
  });

  const createBackend = useCreateBackend();
  const updateBackend = useUpdateBackend();
  const deleteBackend = useDeleteBackend();

  const handleCreate = async () => {
    try {
      await createBackend.mutateAsync(formData);
      toast.success("Backend created successfully");
      setIsCreateDialogOpen(false);
      setFormData(defaultFormData);
    } catch {
      toast.error("Failed to create backend");
    }
  };

  const handleUpdate = async () => {
    if (!selectedBackend) return;
    try {
      await updateBackend.mutateAsync({ id: selectedBackend.id, ...formData });
      toast.success("Backend updated successfully");
      setIsEditDialogOpen(false);
      setSelectedBackend(null);
      setFormData(defaultFormData);
    } catch {
      toast.error("Failed to update backend");
    }
  };

  const handleDelete = async () => {
    if (!selectedBackend) return;
    try {
      await deleteBackend.mutateAsync(selectedBackend.id);
      toast.success("Backend deleted successfully");
      setIsDeleteDialogOpen(false);
      setSelectedBackend(null);
    } catch {
      toast.error("Failed to delete backend");
    }
  };

  const handleToggleActive = async (backend: Backend) => {
    try {
      await updateBackend.mutateAsync({
        id: backend.id,
        isActive: !backend.isActive,
      });
      toast.success(
        `Backend ${backend.isActive ? "disabled" : "enabled"} successfully`
      );
    } catch {
      toast.error("Failed to update backend status");
    }
  };

  const openEditDialog = (backend: Backend) => {
    setSelectedBackend(backend);
    setFormData({
      name: backend.name,
      host: backend.host,
      port: backend.port,
      protocol: backend.protocol,
      healthCheckPath: backend.healthCheckPath,
      healthCheckInterval: backend.healthCheckInterval,
      weight: backend.weight,
      isActive: backend.isActive,
    });
    setIsEditDialogOpen(true);
  };

  const openDeleteDialog = (backend: Backend) => {
    setSelectedBackend(backend);
    setIsDeleteDialogOpen(true);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Backends</h1>
          <p className="text-muted-foreground">
            Manage your origin servers and load balancing
          </p>
        </div>
        <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Add Backend
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-[500px]">
            <DialogHeader>
              <DialogTitle>Add New Backend</DialogTitle>
              <DialogDescription>
                Configure a new origin server for your traffic
              </DialogDescription>
            </DialogHeader>
            <BackendForm formData={formData} setFormData={setFormData} />
            <DialogFooter>
              <Button
                variant="outline"
                onClick={() => setIsCreateDialogOpen(false)}
              >
                Cancel
              </Button>
              <Button onClick={handleCreate} disabled={createBackend.isPending}>
                {createBackend.isPending ? "Creating..." : "Create Backend"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Backends</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{backends?.length || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active</CardTitle>
            <Power className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {backends?.filter((b) => b.isActive).length || 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Inactive</CardTitle>
            <PowerOff className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {backends?.filter((b) => !b.isActive).length || 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Weight</CardTitle>
            <RefreshCw className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {backends?.reduce((sum, b) => sum + (b.isActive ? b.weight : 0), 0) ||
                0}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Backends Table */}
      <Card>
        <CardHeader>
          <CardTitle>Origin Servers</CardTitle>
          <CardDescription>
            Configure and manage your backend servers
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-4">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-16 w-full" />
              ))}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Host</TableHead>
                  <TableHead>Protocol</TableHead>
                  <TableHead>Health Check</TableHead>
                  <TableHead>Weight</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="w-[70px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {backends?.map((backend) => (
                  <TableRow key={backend.id}>
                    <TableCell className="font-medium">
                      <div className="flex items-center gap-2">
                        <Server className="h-4 w-4 text-muted-foreground" />
                        {backend.name}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm">
                          {backend.host}:{backend.port}
                        </span>
                        <a
                          href={`${backend.protocol}://${backend.host}:${backend.port}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-muted-foreground hover:text-foreground"
                        >
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="uppercase">
                        {backend.protocol}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="text-sm">
                        <div className="font-mono">{backend.healthCheckPath}</div>
                        <div className="text-muted-foreground">
                          every {backend.healthCheckInterval}s
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">{backend.weight}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={backend.isActive ? "success" : "secondary"}
                      >
                        {backend.isActive ? "Active" : "Inactive"}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem
                            onClick={() => openEditDialog(backend)}
                          >
                            <Pencil className="mr-2 h-4 w-4" />
                            Edit
                          </DropdownMenuItem>
                          <DropdownMenuItem
                            onClick={() => handleToggleActive(backend)}
                          >
                            {backend.isActive ? (
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
                            onClick={() => openDeleteDialog(backend)}
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

      {/* Edit Dialog */}
      <Dialog open={isEditDialogOpen} onOpenChange={setIsEditDialogOpen}>
        <DialogContent className="sm:max-w-[500px]">
          <DialogHeader>
            <DialogTitle>Edit Backend</DialogTitle>
            <DialogDescription>
              Update the configuration for {selectedBackend?.name}
            </DialogDescription>
          </DialogHeader>
          <BackendForm formData={formData} setFormData={setFormData} />
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setIsEditDialogOpen(false)}
            >
              Cancel
            </Button>
            <Button onClick={handleUpdate} disabled={updateBackend.isPending}>
              {updateBackend.isPending ? "Saving..." : "Save Changes"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={isDeleteDialogOpen} onOpenChange={setIsDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Backend</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{selectedBackend?.name}"? This
              action cannot be undone and will remove all traffic routing to this
              backend.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteBackend.isPending ? "Deleting..." : "Delete"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

interface BackendFormProps {
  formData: BackendFormData;
  setFormData: React.Dispatch<React.SetStateAction<BackendFormData>>;
}

function BackendForm({ formData, setFormData }: BackendFormProps) {
  return (
    <div className="grid gap-4 py-4">
      <div className="grid gap-2">
        <Label htmlFor="name">Name</Label>
        <Input
          id="name"
          placeholder="My Backend Server"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
        />
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="grid gap-2">
          <Label htmlFor="host">Host</Label>
          <Input
            id="host"
            placeholder="api.example.com"
            value={formData.host}
            onChange={(e) => setFormData({ ...formData, host: e.target.value })}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="port">Port</Label>
          <Input
            id="port"
            type="number"
            placeholder="443"
            value={formData.port}
            onChange={(e) =>
              setFormData({ ...formData, port: parseInt(e.target.value) || 443 })
            }
          />
        </div>
      </div>
      <div className="grid gap-2">
        <Label htmlFor="protocol">Protocol</Label>
        <Select
          value={formData.protocol}
          onValueChange={(value: "http" | "https") =>
            setFormData({ ...formData, protocol: value })
          }
        >
          <SelectTrigger>
            <SelectValue placeholder="Select protocol" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="https">HTTPS</SelectItem>
            <SelectItem value="http">HTTP</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="grid gap-2">
          <Label htmlFor="healthCheckPath">Health Check Path</Label>
          <Input
            id="healthCheckPath"
            placeholder="/health"
            value={formData.healthCheckPath}
            onChange={(e) =>
              setFormData({ ...formData, healthCheckPath: e.target.value })
            }
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="healthCheckInterval">Interval (seconds)</Label>
          <Input
            id="healthCheckInterval"
            type="number"
            placeholder="30"
            value={formData.healthCheckInterval}
            onChange={(e) =>
              setFormData({
                ...formData,
                healthCheckInterval: parseInt(e.target.value) || 30,
              })
            }
          />
        </div>
      </div>
      <div className="grid gap-2">
        <Label htmlFor="weight">Weight</Label>
        <Input
          id="weight"
          type="number"
          placeholder="100"
          value={formData.weight}
          onChange={(e) =>
            setFormData({ ...formData, weight: parseInt(e.target.value) || 100 })
          }
        />
        <p className="text-xs text-muted-foreground">
          Higher weight means more traffic will be routed to this backend
        </p>
      </div>
      <div className="flex items-center justify-between">
        <Label htmlFor="isActive">Active</Label>
        <Switch
          id="isActive"
          checked={formData.isActive}
          onCheckedChange={(checked) =>
            setFormData({ ...formData, isActive: checked })
          }
        />
      </div>
    </div>
  );
}
