import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import {
  AlertTriangle,
  Ban,
  Building2,
  Check,
  Eye,
  Key,
  Loader2,
  Mail,
  MoreVertical,
  Search,
  Shield,
  ShieldOff,
  User as UserIcon,
  UserX,
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useTRPC } from "@/lib/trpc/client";

export const Route = createFileRoute("/admin/users")({
  component: AdminUsers,
});

function AdminUsers() {
  const [searchQuery, setSearchQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [actionDialogOpen, setActionDialogOpen] = useState(false);
  const [actionType, setActionType] = useState<
    "ban" | "unban" | "makeAdmin" | "removeAdmin" | null
  >(null);
  const [banReason, setBanReason] = useState("");

  const trpc = useTRPC();
  const queryClient = useQueryClient();

  // List users
  const { data: usersData, isLoading } = useQuery(
    trpc.admin.listUsers.queryOptions({
      search: searchQuery || undefined,
      role: roleFilter !== "all" ? (roleFilter as "user" | "admin") : undefined,
      banned:
        statusFilter === "banned"
          ? true
          : statusFilter === "active"
            ? false
            : undefined,
      limit: 50,
    }),
  );

  const users = usersData?.users ?? [];

  // Get user details
  const { data: selectedUser } = useQuery({
    ...trpc.admin.getUser.queryOptions({ id: selectedUserId ?? "" }),
    enabled: !!selectedUserId,
  });

  // Ban user mutation
  const banMutation = useMutation(
    trpc.admin.banUser.mutationOptions({
      onSuccess: () => {
        toast.success("User banned");
        closeDialog();
        queryClient.invalidateQueries({ queryKey: ["admin", "listUsers"] });
      },
      onError: (error) => {
        toast.error(`Failed to ban user: ${error.message}`);
      },
    }),
  );

  // Unban user mutation
  const unbanMutation = useMutation(
    trpc.admin.unbanUser.mutationOptions({
      onSuccess: () => {
        toast.success("User unbanned");
        closeDialog();
        queryClient.invalidateQueries({ queryKey: ["admin", "listUsers"] });
      },
      onError: (error) => {
        toast.error(`Failed to unban user: ${error.message}`);
      },
    }),
  );

  // Update user role mutation
  const updateRoleMutation = useMutation(
    trpc.admin.updateUserRole.mutationOptions({
      onSuccess: () => {
        toast.success("User role updated");
        closeDialog();
        queryClient.invalidateQueries({ queryKey: ["admin", "listUsers"] });
      },
      onError: (error) => {
        toast.error(`Failed to update user role: ${error.message}`);
      },
    }),
  );

  function openActionDialog(userId: string, type: typeof actionType) {
    setSelectedUserId(userId);
    setActionType(type);
    setActionDialogOpen(true);
  }

  function closeDialog() {
    setActionDialogOpen(false);
    setSelectedUserId(null);
    setActionType(null);
    setBanReason("");
  }

  function executeAction() {
    if (!selectedUserId || !actionType) return;

    switch (actionType) {
      case "ban":
        banMutation.mutate({
          userId: selectedUserId,
          reason: banReason || "Banned by admin",
        });
        break;
      case "unban":
        unbanMutation.mutate({ userId: selectedUserId });
        break;
      case "makeAdmin":
        updateRoleMutation.mutate({ userId: selectedUserId, role: "admin" });
        break;
      case "removeAdmin":
        updateRoleMutation.mutate({ userId: selectedUserId, role: "user" });
        break;
    }
  }

  const getActionDialogContent = () => {
    const user = users?.find((u) => u.id === selectedUserId);
    if (!user) return null;

    switch (actionType) {
      case "ban":
        return {
          title: "Ban User",
          description: `Are you sure you want to ban ${user.email}? They will not be able to log in.`,
          variant: "destructive" as const,
          confirmText: "Ban User",
          showReasonInput: true,
        };
      case "unban":
        return {
          title: "Unban User",
          description: `Are you sure you want to unban ${user.email}? They will be able to log in again.`,
          variant: "default" as const,
          confirmText: "Unban User",
          showReasonInput: false,
        };
      case "makeAdmin":
        return {
          title: "Make Admin",
          description: `Promote ${user.email} to admin? They will have full platform access.`,
          variant: "warning" as const,
          confirmText: "Make Admin",
          showReasonInput: false,
        };
      case "removeAdmin":
        return {
          title: "Remove Admin Role",
          description: `Remove admin privileges from ${user.email}?`,
          variant: "warning" as const,
          confirmText: "Remove Admin",
          showReasonInput: false,
        };
      default:
        return null;
    }
  };

  const dialogContent = getActionDialogContent();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">User Management</h1>
        <p className="text-muted-foreground">
          Manage users across the platform
        </p>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Users</CardTitle>
            <UserIcon className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{users?.length ?? 0}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Admins</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {users?.filter((u) => u.role === "admin").length ?? 0}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Banned</CardTitle>
            <UserX className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {users?.filter((u) => u.banned).length ?? 0}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">2FA Enabled</CardTitle>
            <Key className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {users?.filter((u) => u.twoFactorEnabled).length ?? 0}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex flex-col gap-4 md:flex-row md:items-center">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search by email or name..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>

            <Select value={roleFilter} onValueChange={setRoleFilter}>
              <SelectTrigger className="w-[150px]">
                <SelectValue placeholder="Role" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Roles</SelectItem>
                <SelectItem value="user">User</SelectItem>
                <SelectItem value="admin">Admin</SelectItem>
              </SelectContent>
            </Select>

            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[150px]">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="banned">Banned</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Users Table */}
      <Card>
        <CardHeader>
          <CardTitle>Users</CardTitle>
          <CardDescription>
            {users?.length ?? 0} users match your filters
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Organizations</TableHead>
                  <TableHead>Security</TableHead>
                  <TableHead>Last Login</TableHead>
                  <TableHead className="w-[50px]" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {users?.map((user) => (
                  <TableRow key={user.id}>
                    <TableCell>
                      <div className="flex items-center gap-3">
                        <div className="flex h-10 w-10 items-center justify-center rounded-full bg-muted">
                          {user.avatar ? (
                            <img
                              src={user.avatar}
                              alt={user.name ?? user.email}
                              className="h-10 w-10 rounded-full"
                            />
                          ) : (
                            <UserIcon className="h-5 w-5 text-muted-foreground" />
                          )}
                        </div>
                        <div>
                          <p className="font-medium">{user.name || "—"}</p>
                          <p className="text-sm text-muted-foreground">
                            {user.email}
                          </p>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={user.banned ? "destructive" : "default"}>
                        {user.banned ? "Banned" : "Active"}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={user.role === "admin" ? "default" : "outline"}
                      >
                        {user.role === "admin" ? (
                          <Shield className="mr-1 h-3 w-3" />
                        ) : null}
                        {user.role}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Building2 className="h-4 w-4 text-muted-foreground" />-
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        {user.emailVerified ? (
                          <Badge variant="outline" className="gap-1">
                            <Mail className="h-3 w-3" />
                            Verified
                          </Badge>
                        ) : (
                          <Badge variant="secondary" className="gap-1">
                            <Mail className="h-3 w-3" />
                            Unverified
                          </Badge>
                        )}
                        {user.twoFactorEnabled && (
                          <Badge variant="outline" className="gap-1">
                            <Key className="h-3 w-3" />
                            2FA
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-muted-foreground">
                        {user.lastLoginAt
                          ? formatTimeAgo(user.lastLoginAt)
                          : "Never"}
                      </span>
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="sm">
                            <MoreVertical className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem
                            onClick={() => setSelectedUserId(user.id)}
                          >
                            <Eye className="mr-2 h-4 w-4" />
                            View Details
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          {user.role === "admin" ? (
                            <DropdownMenuItem
                              onClick={() =>
                                openActionDialog(user.id, "removeAdmin")
                              }
                            >
                              <ShieldOff className="mr-2 h-4 w-4" />
                              Remove Admin
                            </DropdownMenuItem>
                          ) : (
                            <DropdownMenuItem
                              onClick={() =>
                                openActionDialog(user.id, "makeAdmin")
                              }
                            >
                              <Shield className="mr-2 h-4 w-4" />
                              Make Admin
                            </DropdownMenuItem>
                          )}
                          <DropdownMenuSeparator />
                          {user.banned ? (
                            <DropdownMenuItem
                              onClick={() => openActionDialog(user.id, "unban")}
                            >
                              <Check className="mr-2 h-4 w-4" />
                              Unban User
                            </DropdownMenuItem>
                          ) : (
                            <DropdownMenuItem
                              className="text-destructive"
                              onClick={() => openActionDialog(user.id, "ban")}
                            >
                              <Ban className="mr-2 h-4 w-4" />
                              Ban User
                            </DropdownMenuItem>
                          )}
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

      {/* User Details Dialog */}
      <Dialog
        open={!!selectedUserId && !actionDialogOpen}
        onOpenChange={(open) => !open && setSelectedUserId(null)}
      >
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>User Details</DialogTitle>
            <DialogDescription>
              View detailed information about this user
            </DialogDescription>
          </DialogHeader>

          {selectedUser && (
            <Tabs defaultValue="profile">
              <TabsList>
                <TabsTrigger value="profile">Profile</TabsTrigger>
                <TabsTrigger value="organizations">Organizations</TabsTrigger>
                <TabsTrigger value="sessions">Sessions</TabsTrigger>
                <TabsTrigger value="activity">Activity</TabsTrigger>
              </TabsList>

              <TabsContent value="profile" className="space-y-4">
                <div className="flex items-center gap-4">
                  <div className="flex h-16 w-16 items-center justify-center rounded-full bg-muted">
                    {selectedUser.avatar ? (
                      <img
                        src={selectedUser.avatar}
                        alt={selectedUser.name ?? selectedUser.email}
                        className="h-16 w-16 rounded-full"
                      />
                    ) : (
                      <UserIcon className="h-8 w-8 text-muted-foreground" />
                    )}
                  </div>
                  <div>
                    <h3 className="text-xl font-semibold">
                      {selectedUser.name || "No name set"}
                    </h3>
                    <p className="text-muted-foreground">
                      {selectedUser.email}
                    </p>
                  </div>
                </div>

                <div className="grid gap-4 md:grid-cols-2">
                  <div>
                    <Label>User ID</Label>
                    <p className="font-mono text-sm">{selectedUser.id}</p>
                  </div>
                  <div>
                    <Label>Role</Label>
                    <p className="capitalize">{selectedUser.role}</p>
                  </div>
                  <div>
                    <Label>Status</Label>
                    <p>{selectedUser.banned ? "Banned" : "Active"}</p>
                    {selectedUser.banReason && (
                      <p className="text-sm text-muted-foreground">
                        Reason: {selectedUser.banReason}
                      </p>
                    )}
                  </div>
                  <div>
                    <Label>Email Verified</Label>
                    <p>{selectedUser.emailVerified ? "Yes" : "No"}</p>
                  </div>
                  <div>
                    <Label>2FA Enabled</Label>
                    <p>{selectedUser.twoFactorEnabled ? "Yes" : "No"}</p>
                  </div>
                  <div>
                    <Label>Created</Label>
                    <p>
                      {new Date(selectedUser.createdAt).toLocaleDateString()}
                    </p>
                  </div>
                  <div>
                    <Label>Updated</Label>
                    <p>
                      {selectedUser.updatedAt
                        ? new Date(selectedUser.updatedAt).toLocaleString()
                        : "Never"}
                    </p>
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="organizations">
                <p className="text-muted-foreground">
                  User is a member of {selectedUser.members?.length ?? 0}{" "}
                  organization(s).
                </p>
                {selectedUser.members && selectedUser.members.length > 0 && (
                  <div className="mt-4 space-y-2">
                    {selectedUser.members.map((member) => (
                      <div
                        key={member.organization?.id}
                        className="flex items-center justify-between p-2 rounded border"
                      >
                        <span>{member.organization?.name}</span>
                        <Badge variant="outline">{member.role}</Badge>
                      </div>
                    ))}
                  </div>
                )}
              </TabsContent>

              <TabsContent value="sessions">
                <p className="text-muted-foreground">
                  Active sessions will be shown here.
                </p>
                {/* Would list active sessions here */}
              </TabsContent>

              <TabsContent value="activity">
                <p className="text-muted-foreground">
                  Recent activity will be shown here.
                </p>
                {/* Would show audit log here */}
              </TabsContent>
            </Tabs>
          )}
        </DialogContent>
      </Dialog>

      {/* Action Confirmation Dialog */}
      <Dialog open={actionDialogOpen} onOpenChange={closeDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {dialogContent?.variant === "destructive" ? (
                <AlertTriangle className="h-5 w-5 text-destructive" />
              ) : dialogContent?.variant === "warning" ? (
                <AlertTriangle className="h-5 w-5 text-yellow-500" />
              ) : null}
              {dialogContent?.title}
            </DialogTitle>
            <DialogDescription>{dialogContent?.description}</DialogDescription>
          </DialogHeader>
          {dialogContent?.showReasonInput && (
            <div className="py-4">
              <Label htmlFor="ban-reason">Reason (optional)</Label>
              <Input
                id="ban-reason"
                value={banReason}
                onChange={(e) => setBanReason(e.target.value)}
                placeholder="Enter ban reason..."
                className="mt-2"
              />
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={closeDialog}>
              Cancel
            </Button>
            <Button
              variant={
                dialogContent?.variant === "destructive"
                  ? "destructive"
                  : "default"
              }
              onClick={executeAction}
              disabled={
                banMutation.isPending ||
                unbanMutation.isPending ||
                updateRoleMutation.isPending
              }
            >
              {(banMutation.isPending ||
                unbanMutation.isPending ||
                updateRoleMutation.isPending) && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              {dialogContent?.confirmText}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function formatTimeAgo(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - new Date(date).getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${diffDays}d ago`;
}
