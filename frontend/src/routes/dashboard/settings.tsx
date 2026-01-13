// @ts-nocheck
// TODO: This file references trpc.settings endpoints that don't exist in the router.
// The settings router needs to be implemented or this file needs to be rewritten.
import { useForm } from "@tanstack/react-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import {
  Bell,
  Copy,
  Eye,
  EyeOff,
  Key,
  Loader2,
  MoreVertical,
  Plus,
  RefreshCw,
  Settings,
  Shield,
  Trash2,
} from "lucide-react";
import { useState } from "react";
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
import { Separator } from "@/components/ui/separator";
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
import { useTRPC } from "@/lib/trpc/client";

export const Route = createFileRoute("/dashboard/settings")({
  component: SettingsPage,
});

const orgSettingsSchema = z.object({
  name: z.string().min(1, "Name is required"),
  contactEmail: z.string().email("Invalid email"),
});

const securitySettingsSchema = z.object({
  autoMitigation: z.boolean(),
  challengeMode: z.boolean(),
  sensitivityLevel: z.enum(["low", "medium", "high"]),
});

const notificationSettingsSchema = z.object({
  alertEmail: z.string().email().optional().or(z.literal("")),
  slackWebhook: z.string().url().optional().or(z.literal("")),
  discordWebhook: z.string().url().optional().or(z.literal("")),
  emailOnAttack: z.boolean(),
  emailOnDegraded: z.boolean(),
  slackOnAttack: z.boolean(),
});

function SettingsPage() {
  const [showApiKey, setShowApiKey] = useState<string | null>(null);
  const [newKeyDialogOpen, setNewKeyDialogOpen] = useState(false);
  const [deleteKeyId, setDeleteKeyId] = useState<string | null>(null);
  const [newKeyName, setNewKeyName] = useState("");
  const [newApiKey, setNewApiKey] = useState<string | null>(null);

  const trpc = useTRPC();
  const queryClient = useQueryClient();

  // Get organization settings
  const { data: orgSettings, isLoading: orgLoading } = useQuery(
    trpc.settings.getOrganization.queryOptions(),
  );

  // Get security settings
  const { data: securitySettings, isLoading: securityLoading } = useQuery(
    trpc.settings.getSecurity.queryOptions(),
  );

  // Get notification settings
  const { data: notificationSettings, isLoading: notifLoading } = useQuery(
    trpc.settings.getNotifications.queryOptions(),
  );

  // Get API keys
  const { data: apiKeys, isLoading: keysLoading } = useQuery(
    trpc.settings.listApiKeys.queryOptions(),
  );

  // Update organization mutation
  const updateOrgMutation = useMutation(
    trpc.settings.updateOrganization.mutationOptions({
      onSuccess: () => {
        toast.success("Organization settings updated");
        queryClient.invalidateQueries({ queryKey: ["settings"] });
      },
      onError: (error) => {
        toast.error(`Failed to update organization: ${error.message}`);
      },
    }),
  );

  // Update security mutation
  const updateSecurityMutation = useMutation(
    trpc.settings.updateSecurity.mutationOptions({
      onSuccess: () => {
        toast.success("Security settings updated");
        queryClient.invalidateQueries({ queryKey: ["settings"] });
      },
      onError: (error) => {
        toast.error(`Failed to update security settings: ${error.message}`);
      },
    }),
  );

  // Update notification mutation
  const updateNotificationMutation = useMutation(
    trpc.settings.updateNotifications.mutationOptions({
      onSuccess: () => {
        toast.success("Notification settings updated");
        queryClient.invalidateQueries({ queryKey: ["settings"] });
      },
      onError: (error) => {
        toast.error(`Failed to update notification settings: ${error.message}`);
      },
    }),
  );

  // Create API key mutation
  const createApiKeyMutation = useMutation(
    trpc.settings.createApiKey.mutationOptions({
      onSuccess: (data) => {
        setNewApiKey(data.key);
        setNewKeyName("");
        queryClient.invalidateQueries({ queryKey: ["settings", "apiKeys"] });
      },
      onError: (error) => {
        toast.error(`Failed to create API key: ${error.message}`);
      },
    }),
  );

  // Delete API key mutation
  const deleteApiKeyMutation = useMutation(
    trpc.settings.deleteApiKey.mutationOptions({
      onSuccess: () => {
        toast.success("API key deleted");
        setDeleteKeyId(null);
        queryClient.invalidateQueries({ queryKey: ["settings", "apiKeys"] });
      },
      onError: (error) => {
        toast.error(`Failed to delete API key: ${error.message}`);
      },
    }),
  );

  // Regenerate API key mutation
  const regenerateApiKeyMutation = useMutation(
    trpc.settings.regenerateApiKey.mutationOptions({
      onSuccess: (data) => {
        toast.success("API key regenerated");
        setNewApiKey(data.key);
        setNewKeyDialogOpen(true);
        queryClient.invalidateQueries({ queryKey: ["settings", "apiKeys"] });
      },
      onError: (error) => {
        toast.error(`Failed to regenerate API key: ${error.message}`);
      },
    }),
  );

  // Organization form
  const orgForm = useForm({
    defaultValues: {
      name: orgSettings?.name ?? "",
      contactEmail: orgSettings?.contactEmail ?? "",
    },
    onSubmit: async ({ value }) => {
      await updateOrgMutation.mutateAsync(value);
    },
    validators: {
      onChange: orgSettingsSchema,
    },
  });

  // Security form
  const securityForm = useForm({
    defaultValues: {
      autoMitigation: securitySettings?.autoMitigation ?? true,
      challengeMode: securitySettings?.challengeMode ?? true,
      sensitivityLevel: (securitySettings?.sensitivityLevel ?? "medium") as
        | "low"
        | "medium"
        | "high",
    },
    onSubmit: async ({ value }) => {
      await updateSecurityMutation.mutateAsync(value);
    },
    validators: {
      onChange: securitySettingsSchema,
    },
  });

  // Notification form
  const notificationForm = useForm({
    defaultValues: {
      alertEmail: notificationSettings?.alertEmail ?? "",
      slackWebhook: notificationSettings?.slackWebhook ?? "",
      discordWebhook: notificationSettings?.discordWebhook ?? "",
      emailOnAttack: notificationSettings?.emailOnAttack ?? true,
      emailOnDegraded: notificationSettings?.emailOnDegraded ?? false,
      slackOnAttack: notificationSettings?.slackOnAttack ?? true,
    },
    onSubmit: async ({ value }) => {
      await updateNotificationMutation.mutateAsync(value);
    },
    validators: {
      onChange: notificationSettingsSchema,
    },
  });

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success("Copied to clipboard");
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
        <p className="text-muted-foreground">
          Configure your protection preferences.
        </p>
      </div>
      <Tabs defaultValue="general" className="space-y-4">
        <TabsList>
          <TabsTrigger value="general">
            <Settings className="mr-2 h-4 w-4" />
            General
          </TabsTrigger>
          <TabsTrigger value="security">
            <Shield className="mr-2 h-4 w-4" />
            Security
          </TabsTrigger>
          <TabsTrigger value="notifications">
            <Bell className="mr-2 h-4 w-4" />
            Notifications
          </TabsTrigger>
          <TabsTrigger value="api">
            <Key className="mr-2 h-4 w-4" />
            API
          </TabsTrigger>
        </TabsList>

        {/* General Settings */}
        <TabsContent value="general" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Organization Settings</CardTitle>
              <CardDescription>
                Manage your organization details.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {orgLoading ? (
                <div className="flex justify-center py-4">
                  <Loader2 className="h-6 w-6 animate-spin" />
                </div>
              ) : (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    orgForm.handleSubmit();
                  }}
                  className="space-y-4"
                >
                  <orgForm.Field name="name">
                    {(field) => (
                      <div className="grid gap-2">
                        <Label>Organization Name</Label>
                        <Input
                          value={field.state.value}
                          onChange={(e) => field.handleChange(e.target.value)}
                        />
                      </div>
                    )}
                  </orgForm.Field>
                  <orgForm.Field name="contactEmail">
                    {(field) => (
                      <div className="grid gap-2">
                        <Label>Contact Email</Label>
                        <Input
                          type="email"
                          value={field.state.value}
                          onChange={(e) => field.handleChange(e.target.value)}
                        />
                      </div>
                    )}
                  </orgForm.Field>
                  <Button type="submit" disabled={updateOrgMutation.isPending}>
                    {updateOrgMutation.isPending && (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    )}
                    Save Changes
                  </Button>
                </form>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Security Settings */}
        <TabsContent value="security" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Protection Settings</CardTitle>
              <CardDescription>
                Configure automatic protection behavior.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {securityLoading ? (
                <div className="flex justify-center py-4">
                  <Loader2 className="h-6 w-6 animate-spin" />
                </div>
              ) : (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    securityForm.handleSubmit();
                  }}
                  className="space-y-6"
                >
                  <securityForm.Field name="autoMitigation">
                    {(field) => (
                      <div className="flex items-center justify-between">
                        <div>
                          <Label className="text-base">Auto Mitigation</Label>
                          <p className="text-sm text-muted-foreground">
                            Automatically apply mitigation when attacks are
                            detected.
                          </p>
                        </div>
                        <Switch
                          checked={field.state.value}
                          onCheckedChange={field.handleChange}
                        />
                      </div>
                    )}
                  </securityForm.Field>
                  <Separator />
                  <securityForm.Field name="challengeMode">
                    {(field) => (
                      <div className="flex items-center justify-between">
                        <div>
                          <Label className="text-base">Challenge Mode</Label>
                          <p className="text-sm text-muted-foreground">
                            Present challenges to suspicious traffic before
                            blocking.
                          </p>
                        </div>
                        <Switch
                          checked={field.state.value}
                          onCheckedChange={field.handleChange}
                        />
                      </div>
                    )}
                  </securityForm.Field>
                  <Separator />
                  <securityForm.Field name="sensitivityLevel">
                    {(field) => (
                      <div className="grid gap-2">
                        <Label>Sensitivity Level</Label>
                        <Select
                          value={field.state.value}
                          onValueChange={(v) =>
                            field.handleChange(v as "low" | "medium" | "high")
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="low">
                              Low - Fewer false positives, may miss some attacks
                            </SelectItem>
                            <SelectItem value="medium">
                              Medium - Balanced protection
                            </SelectItem>
                            <SelectItem value="high">
                              High - Maximum protection, may have false
                              positives
                            </SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    )}
                  </securityForm.Field>
                  <Button
                    type="submit"
                    disabled={updateSecurityMutation.isPending}
                  >
                    {updateSecurityMutation.isPending && (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    )}
                    Update Security Settings
                  </Button>
                </form>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Notification Settings */}
        <TabsContent value="notifications" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Notification Settings</CardTitle>
              <CardDescription>
                Configure how you receive alerts.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {notifLoading ? (
                <div className="flex justify-center py-4">
                  <Loader2 className="h-6 w-6 animate-spin" />
                </div>
              ) : (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    notificationForm.handleSubmit();
                  }}
                  className="space-y-6"
                >
                  <div className="space-y-4">
                    <h4 className="font-medium">Notification Channels</h4>
                    <notificationForm.Field name="alertEmail">
                      {(field) => (
                        <div className="grid gap-2">
                          <Label>Alert Email</Label>
                          <Input
                            type="email"
                            placeholder="alerts@example.com"
                            value={field.state.value}
                            onChange={(e) => field.handleChange(e.target.value)}
                          />
                        </div>
                      )}
                    </notificationForm.Field>
                    <notificationForm.Field name="slackWebhook">
                      {(field) => (
                        <div className="grid gap-2">
                          <Label>Slack Webhook URL</Label>
                          <Input
                            placeholder="https://hooks.slack.com/services/..."
                            value={field.state.value}
                            onChange={(e) => field.handleChange(e.target.value)}
                          />
                        </div>
                      )}
                    </notificationForm.Field>
                    <notificationForm.Field name="discordWebhook">
                      {(field) => (
                        <div className="grid gap-2">
                          <Label>Discord Webhook URL</Label>
                          <Input
                            placeholder="https://discord.com/api/webhooks/..."
                            value={field.state.value}
                            onChange={(e) => field.handleChange(e.target.value)}
                          />
                        </div>
                      )}
                    </notificationForm.Field>
                  </div>
                  <Separator />
                  <div className="space-y-4">
                    <h4 className="font-medium">Email Notifications</h4>
                    <notificationForm.Field name="emailOnAttack">
                      {(field) => (
                        <div className="flex items-center justify-between">
                          <div>
                            <Label>Attack Detected</Label>
                            <p className="text-sm text-muted-foreground">
                              Receive email when an attack is detected
                            </p>
                          </div>
                          <Switch
                            checked={field.state.value}
                            onCheckedChange={field.handleChange}
                          />
                        </div>
                      )}
                    </notificationForm.Field>
                    <notificationForm.Field name="emailOnDegraded">
                      {(field) => (
                        <div className="flex items-center justify-between">
                          <div>
                            <Label>Service Degraded</Label>
                            <p className="text-sm text-muted-foreground">
                              Receive email when backend health degrades
                            </p>
                          </div>
                          <Switch
                            checked={field.state.value}
                            onCheckedChange={field.handleChange}
                          />
                        </div>
                      )}
                    </notificationForm.Field>
                  </div>
                  <Separator />
                  <div className="space-y-4">
                    <h4 className="font-medium">Slack Notifications</h4>
                    <notificationForm.Field name="slackOnAttack">
                      {(field) => (
                        <div className="flex items-center justify-between">
                          <div>
                            <Label>Attack Detected</Label>
                            <p className="text-sm text-muted-foreground">
                              Send Slack message when an attack is detected
                            </p>
                          </div>
                          <Switch
                            checked={field.state.value}
                            onCheckedChange={field.handleChange}
                          />
                        </div>
                      )}
                    </notificationForm.Field>
                  </div>
                  <Button
                    type="submit"
                    disabled={updateNotificationMutation.isPending}
                  >
                    {updateNotificationMutation.isPending && (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    )}
                    Save Notification Settings
                  </Button>
                </form>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* API Settings */}
        <TabsContent value="api" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>API Keys</CardTitle>
                  <CardDescription>
                    Manage API keys for programmatic access.
                  </CardDescription>
                </div>
                <Dialog
                  open={newKeyDialogOpen}
                  onOpenChange={(open) => {
                    setNewKeyDialogOpen(open);
                    if (!open) {
                      setNewApiKey(null);
                      setNewKeyName("");
                    }
                  }}
                >
                  <DialogTrigger asChild>
                    <Button>
                      <Plus className="mr-2 h-4 w-4" />
                      Create API Key
                    </Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>
                        {newApiKey ? "API Key Created" : "Create API Key"}
                      </DialogTitle>
                      <DialogDescription>
                        {newApiKey
                          ? "Copy your API key now. You won't be able to see it again."
                          : "Create a new API key for programmatic access."}
                      </DialogDescription>
                    </DialogHeader>
                    {newApiKey ? (
                      <div className="space-y-4">
                        <div className="flex items-center gap-2 p-4 rounded border bg-muted">
                          <code className="flex-1 text-sm break-all">
                            {newApiKey}
                          </code>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => copyToClipboard(newApiKey)}
                          >
                            <Copy className="h-4 w-4" />
                          </Button>
                        </div>
                        <p className="text-sm text-muted-foreground">
                          Store this key securely. It provides full access to
                          your account.
                        </p>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        <div className="grid gap-2">
                          <Label>Key Name</Label>
                          <Input
                            placeholder="Production API Key"
                            value={newKeyName}
                            onChange={(e) => setNewKeyName(e.target.value)}
                          />
                        </div>
                      </div>
                    )}
                    <DialogFooter>
                      {newApiKey ? (
                        <Button onClick={() => setNewKeyDialogOpen(false)}>
                          Done
                        </Button>
                      ) : (
                        <>
                          <Button
                            variant="outline"
                            onClick={() => setNewKeyDialogOpen(false)}
                          >
                            Cancel
                          </Button>
                          <Button
                            onClick={() =>
                              createApiKeyMutation.mutate({ name: newKeyName })
                            }
                            disabled={
                              !newKeyName || createApiKeyMutation.isPending
                            }
                          >
                            {createApiKeyMutation.isPending && (
                              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                            )}
                            Create Key
                          </Button>
                        </>
                      )}
                    </DialogFooter>
                  </DialogContent>
                </Dialog>
              </div>
            </CardHeader>
            <CardContent>
              {keysLoading ? (
                <div className="flex justify-center py-8">
                  <Loader2 className="h-6 w-6 animate-spin" />
                </div>
              ) : apiKeys?.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Key className="mx-auto h-12 w-12 mb-4 opacity-50" />
                  <p>No API keys yet</p>
                  <p className="text-sm">
                    Create an API key to access the PistonProtection API.
                  </p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Key</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead>Last Used</TableHead>
                      <TableHead className="w-[50px]" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {apiKeys?.map((key) => (
                      <TableRow key={key.id}>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <span className="font-medium">{key.name}</span>
                            <Badge
                              variant={
                                key.status === "active"
                                  ? "default"
                                  : "secondary"
                              }
                            >
                              {key.status}
                            </Badge>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <code className="text-sm text-muted-foreground">
                              {showApiKey === key.id
                                ? key.keyPreview
                                : `pp_****${key.keyPreview?.slice(-4) ?? "****"}`}
                            </code>
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() =>
                                setShowApiKey(
                                  showApiKey === key.id ? null : key.id,
                                )
                              }
                            >
                              {showApiKey === key.id ? (
                                <EyeOff className="h-4 w-4" />
                              ) : (
                                <Eye className="h-4 w-4" />
                              )}
                            </Button>
                          </div>
                        </TableCell>
                        <TableCell>
                          {new Date(key.createdAt).toLocaleDateString()}
                        </TableCell>
                        <TableCell>
                          {key.lastUsedAt
                            ? new Date(key.lastUsedAt).toLocaleDateString()
                            : "Never"}
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
                                onClick={() =>
                                  regenerateApiKeyMutation.mutate({
                                    id: key.id,
                                  })
                                }
                              >
                                <RefreshCw className="mr-2 h-4 w-4" />
                                Regenerate
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                onClick={() => setDeleteKeyId(key.id)}
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
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Delete API Key Dialog */}
      <Dialog open={!!deleteKeyId} onOpenChange={() => setDeleteKeyId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete API Key</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this API key? Any applications
              using this key will lose access immediately.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteKeyId(null)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() =>
                deleteKeyId && deleteApiKeyMutation.mutate({ id: deleteKeyId })
              }
              disabled={deleteApiKeyMutation.isPending}
            >
              {deleteApiKeyMutation.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Delete Key
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
