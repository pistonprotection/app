import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import {
  Ban,
  Building,
  CreditCard,
  Eye,
  Loader2,
  MoreVertical,
  Search,
  Server,
  Shield,
  Users,
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useTRPC } from "@/lib/trpc/client";

export const Route = createFileRoute("/admin/organizations")({
  component: AdminOrganizations,
});

function AdminOrganizations() {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedOrgId, setSelectedOrgId] = useState<string | null>(null);
  const [suspendDialogOpen, setSuspendDialogOpen] = useState(false);

  const trpc = useTRPC();
  const queryClient = useQueryClient();

  // List organizations
  const { data: organizations, isLoading } = useQuery(
    trpc.admin.listOrganizations.queryOptions({
      search: searchQuery || undefined,
      limit: 50,
    }),
  );

  // Get org details
  const { data: selectedOrg } = useQuery({
    ...trpc.admin.getOrganization.queryOptions({
      id: selectedOrgId ?? "",
    }),
    enabled: !!selectedOrgId,
  });

  // Suspend organization mutation
  const suspendMutation = useMutation(
    trpc.admin.suspendOrganization.mutationOptions({
      onSuccess: () => {
        toast.success("Organization suspended");
        setSuspendDialogOpen(false);
        queryClient.invalidateQueries({ queryKey: ["admin", "organizations"] });
      },
      onError: (error) => {
        toast.error(`Failed to suspend organization: ${error.message}`);
      },
    }),
  );

  // Unsuspend organization mutation
  const unsuspendMutation = useMutation(
    trpc.admin.unsuspendOrganization.mutationOptions({
      onSuccess: () => {
        toast.success("Organization unsuspended");
        queryClient.invalidateQueries({ queryKey: ["admin", "organizations"] });
      },
      onError: (error) => {
        toast.error(`Failed to unsuspend organization: ${error.message}`);
      },
    }),
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Organizations</h1>
        <p className="text-muted-foreground">
          Manage all organizations on the platform
        </p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>All Organizations</CardTitle>
              <CardDescription>
                {organizations?.total ?? 0} total organizations
              </CardDescription>
            </div>
            <div className="relative w-64">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search organizations..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center py-8">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Organization</TableHead>
                  <TableHead>Members</TableHead>
                  <TableHead>Backends</TableHead>
                  <TableHead>Plan</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="w-[50px]" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {organizations?.items.map((org) => (
                  <TableRow key={org.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        {org.logo ? (
                          <img
                            src={org.logo}
                            alt={org.name}
                            className="h-8 w-8 rounded"
                          />
                        ) : (
                          <Building className="h-8 w-8 p-1 rounded bg-muted" />
                        )}
                        <div>
                          <p className="font-medium">{org.name}</p>
                          <p className="text-xs text-muted-foreground">
                            {org.slug}
                          </p>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Users className="h-4 w-4 text-muted-foreground" />
                        {org.memberCount}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Server className="h-4 w-4 text-muted-foreground" />
                        {org.backendCount}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{org.plan ?? "Free"}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          org.status === "active"
                            ? "default"
                            : org.status === "suspended"
                              ? "destructive"
                              : "secondary"
                        }
                      >
                        {org.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {new Date(org.createdAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon">
                            <MoreVertical className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem
                            onClick={() => setSelectedOrgId(org.id)}
                          >
                            <Eye className="mr-2 h-4 w-4" />
                            View Details
                          </DropdownMenuItem>
                          <DropdownMenuItem>
                            <CreditCard className="mr-2 h-4 w-4" />
                            Billing
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          {org.status === "suspended" ? (
                            <DropdownMenuItem
                              onClick={() =>
                                unsuspendMutation.mutate({ id: org.id })
                              }
                            >
                              <Shield className="mr-2 h-4 w-4" />
                              Unsuspend
                            </DropdownMenuItem>
                          ) : (
                            <DropdownMenuItem
                              onClick={() => {
                                setSelectedOrgId(org.id);
                                setSuspendDialogOpen(true);
                              }}
                              className="text-destructive focus:text-destructive"
                            >
                              <Ban className="mr-2 h-4 w-4" />
                              Suspend
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

      {/* Organization Details Dialog */}
      <Dialog
        open={!!selectedOrgId && !suspendDialogOpen}
        onOpenChange={() => setSelectedOrgId(null)}
      >
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{selectedOrg?.name}</DialogTitle>
            <DialogDescription>
              Organization details and statistics
            </DialogDescription>
          </DialogHeader>
          {selectedOrg && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-muted-foreground">Slug</p>
                  <p className="font-medium">{selectedOrg.slug}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Status</p>
                  <Badge>{selectedOrg.status}</Badge>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Plan</p>
                  <p className="font-medium">{selectedOrg.plan ?? "Free"}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Created</p>
                  <p className="font-medium">
                    {new Date(selectedOrg.createdAt).toLocaleDateString()}
                  </p>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-4">
                <Card>
                  <CardContent className="pt-4">
                    <div className="text-2xl font-bold">
                      {selectedOrg.memberCount}
                    </div>
                    <p className="text-xs text-muted-foreground">Members</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-4">
                    <div className="text-2xl font-bold">
                      {selectedOrg.backendCount}
                    </div>
                    <p className="text-xs text-muted-foreground">Backends</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-4">
                    <div className="text-2xl font-bold">
                      {formatNumber(selectedOrg.requestsLast24h ?? 0)}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Requests (24h)
                    </p>
                  </CardContent>
                </Card>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Suspend Dialog */}
      <Dialog open={suspendDialogOpen} onOpenChange={setSuspendDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Suspend Organization</DialogTitle>
            <DialogDescription>
              Are you sure you want to suspend this organization? All their
              backends will stop receiving protection.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setSuspendDialogOpen(false)}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() =>
                selectedOrgId &&
                suspendMutation.mutate({
                  id: selectedOrgId,
                  reason: "Admin action",
                })
              }
              disabled={suspendMutation.isPending}
            >
              {suspendMutation.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Suspend
            </Button>
          </DialogFooter>
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
