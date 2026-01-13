import { Check, ChevronsUpDown, Loader2, Plus, Settings } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
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
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useOrganization } from "@/hooks/use-organization";
import { authClient } from "@/lib/auth-client";

interface OrganizationSwitcherProps {
  collapsed?: boolean;
}

export function OrganizationSwitcher({ collapsed }: OrganizationSwitcherProps) {
  const {
    organizationId,
    activeOrganization,
    organizations,
    isLoading,
    setActiveOrganization,
  } = useOrganization();

  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [newOrgName, setNewOrgName] = useState("");
  const [newOrgSlug, setNewOrgSlug] = useState("");
  const [isCreating, setIsCreating] = useState(false);
  const [isSwitching, setIsSwitching] = useState<string | null>(null);

  const handleSwitchOrganization = async (orgId: string) => {
    if (orgId === organizationId) return;
    setIsSwitching(orgId);
    try {
      await setActiveOrganization(orgId);
      toast.success("Switched organization");
    } catch {
      toast.error("Failed to switch organization");
    } finally {
      setIsSwitching(null);
    }
  };

  const handleCreateOrganization = async () => {
    if (!newOrgName.trim()) return;

    setIsCreating(true);
    try {
      const slug =
        newOrgSlug.trim() ||
        newOrgName
          .toLowerCase()
          .replace(/\s+/g, "-")
          .replace(/[^a-z0-9-]/g, "");
      await authClient.organization.create({
        name: newOrgName.trim(),
        slug,
      });
      toast.success("Organization created successfully");
      setCreateDialogOpen(false);
      setNewOrgName("");
      setNewOrgSlug("");
    } catch {
      toast.error("Failed to create organization");
    } finally {
      setIsCreating(false);
    }
  };

  const getInitials = (name: string | undefined | null): string => {
    if (!name) return "??";
    return name
      .split(" ")
      .map((word) => word[0])
      .join("")
      .toUpperCase()
      .slice(0, 2);
  };

  if (isLoading) {
    return (
      <Button variant="ghost" disabled className="w-full justify-start">
        <Loader2 className="h-4 w-4 animate-spin" />
        {!collapsed && <span className="ml-2">Loading...</span>}
      </Button>
    );
  }

  // No organizations - show prompt to create
  if (!organizations || organizations.length === 0) {
    return (
      <>
        <Button
          variant="outline"
          onClick={() => setCreateDialogOpen(true)}
          className="w-full justify-start"
        >
          <Plus className="h-4 w-4" />
          {!collapsed && <span className="ml-2">Create Organization</span>}
        </Button>
        <CreateOrgDialog
          open={createDialogOpen}
          onOpenChange={setCreateDialogOpen}
          newOrgName={newOrgName}
          setNewOrgName={setNewOrgName}
          newOrgSlug={newOrgSlug}
          setNewOrgSlug={setNewOrgSlug}
          isCreating={isCreating}
          onSubmit={handleCreateOrganization}
        />
      </>
    );
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger
          render={
            <Button
              variant="ghost"
              className="w-full justify-start px-2"
              role="combobox"
            />
          }
        >
          <Avatar className="h-6 w-6">
            <AvatarImage src={activeOrganization?.logo ?? undefined} />
            <AvatarFallback className="text-xs">
              {getInitials(activeOrganization?.name)}
            </AvatarFallback>
          </Avatar>
          {!collapsed && (
            <>
              <span className="ml-2 truncate flex-1 text-left">
                {activeOrganization?.name ?? "Select Organization"}
              </span>
              <ChevronsUpDown className="ml-auto h-4 w-4 shrink-0 opacity-50" />
            </>
          )}
        </DropdownMenuTrigger>
        <DropdownMenuContent className="w-[240px]" align="start" sideOffset={4}>
          <DropdownMenuLabel>Organizations</DropdownMenuLabel>
          <DropdownMenuSeparator />
          {organizations.map((org) => (
            <DropdownMenuItem
              key={org.id}
              onClick={() => handleSwitchOrganization(org.id)}
              disabled={isSwitching !== null}
            >
              <Avatar className="h-5 w-5">
                <AvatarImage src={org.logo ?? undefined} />
                <AvatarFallback className="text-xs">
                  {getInitials(org.name)}
                </AvatarFallback>
              </Avatar>
              <span className="ml-2 truncate flex-1">{org.name}</span>
              {org.id === organizationId && (
                <Check className="ml-auto h-4 w-4" />
              )}
              {isSwitching === org.id && (
                <Loader2 className="ml-auto h-4 w-4 animate-spin" />
              )}
            </DropdownMenuItem>
          ))}
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={() => setCreateDialogOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Create Organization
          </DropdownMenuItem>
          {activeOrganization && (
            <DropdownMenuItem
              render={
                <a
                  href="/dashboard/settings"
                  aria-label="Organization Settings"
                >
                  <Settings className="mr-2 h-4 w-4" />
                  Organization Settings
                </a>
              }
            />
          )}
        </DropdownMenuContent>
      </DropdownMenu>

      <CreateOrgDialog
        open={createDialogOpen}
        onOpenChange={setCreateDialogOpen}
        newOrgName={newOrgName}
        setNewOrgName={setNewOrgName}
        newOrgSlug={newOrgSlug}
        setNewOrgSlug={setNewOrgSlug}
        isCreating={isCreating}
        onSubmit={handleCreateOrganization}
      />
    </>
  );
}

interface CreateOrgDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  newOrgName: string;
  setNewOrgName: (name: string) => void;
  newOrgSlug: string;
  setNewOrgSlug: (slug: string) => void;
  isCreating: boolean;
  onSubmit: () => void;
}

function CreateOrgDialog({
  open,
  onOpenChange,
  newOrgName,
  setNewOrgName,
  newOrgSlug,
  setNewOrgSlug,
  isCreating,
  onSubmit,
}: CreateOrgDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create Organization</DialogTitle>
          <DialogDescription>
            Create a new organization to manage your DDoS protection resources.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-4">
          <div className="grid gap-2">
            <Label htmlFor="org-name">Organization Name</Label>
            <Input
              id="org-name"
              placeholder="My Company"
              value={newOrgName}
              onChange={(e) => setNewOrgName(e.target.value)}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="org-slug">
              Slug (optional)
              <span className="text-muted-foreground ml-1 text-xs">
                - URL-friendly identifier
              </span>
            </Label>
            <Input
              id="org-slug"
              placeholder="my-company"
              value={newOrgSlug}
              onChange={(e) =>
                setNewOrgSlug(
                  e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""),
                )
              }
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={onSubmit}
            disabled={!newOrgName.trim() || isCreating}
          >
            {isCreating && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Create Organization
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
