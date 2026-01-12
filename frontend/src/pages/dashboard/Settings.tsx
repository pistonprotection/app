import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  User,
  Shield,
  Key,
  Bell,
  Palette,
  Copy,
  Eye,
  EyeOff,
  Plus,
  Trash2,
  RefreshCw,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
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
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import {
  userQueryOptions,
  apiKeysQueryOptions,
  useUpdateUser,
  useCreateApiKey,
  useDeleteApiKey,
  type ApiKey,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { toast } from "sonner";
import { formatDate } from "@/lib/utils";

// Mock data
const mockUser = {
  id: "1",
  email: "john@example.com",
  name: "John Doe",
  avatar: "",
  role: "owner" as const,
  createdAt: "2024-01-01T00:00:00Z",
};

const mockApiKeys: ApiKey[] = [
  {
    id: "1",
    name: "Production API Key",
    prefix: "pp_live_",
    lastUsed: "2024-01-15T10:30:00Z",
    createdAt: "2024-01-01T00:00:00Z",
    expiresAt: null,
    scopes: ["read", "write"],
  },
  {
    id: "2",
    name: "Development Key",
    prefix: "pp_dev_",
    lastUsed: "2024-01-14T08:00:00Z",
    createdAt: "2024-01-05T00:00:00Z",
    expiresAt: "2024-12-31T23:59:59Z",
    scopes: ["read"],
  },
];

interface ApiKeyFormData {
  name: string;
  scopes: string[];
  expiresIn: string;
}

const defaultApiKeyFormData: ApiKeyFormData = {
  name: "",
  scopes: ["read"],
  expiresIn: "never",
};

export function Settings() {
  useAuth(); // For authentication context
  const [isApiKeyDialogOpen, setIsApiKeyDialogOpen] = useState(false);
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false);
  const [selectedApiKey, setSelectedApiKey] = useState<ApiKey | null>(null);
  const [newApiKey, setNewApiKey] = useState<string | null>(null);
  const [showNewKey, setShowNewKey] = useState(false);
  const [apiKeyFormData, setApiKeyFormData] = useState<ApiKeyFormData>(defaultApiKeyFormData);

  const { data: user, isLoading: userLoading } = useQuery({
    ...userQueryOptions(),
    placeholderData: mockUser,
  });

  const { data: apiKeys, isLoading: apiKeysLoading } = useQuery({
    ...apiKeysQueryOptions(),
    placeholderData: mockApiKeys,
  });

  const updateUser = useUpdateUser();
  const createApiKey = useCreateApiKey();
  const deleteApiKey = useDeleteApiKey();

  const [profileForm, setProfileForm] = useState({
    name: user?.name || "",
    email: user?.email || "",
  });

  const [notifications, setNotifications] = useState({
    email: true,
    attacks: true,
    usage: true,
    newsletter: false,
  });

  const handleUpdateProfile = async () => {
    try {
      await updateUser.mutateAsync(profileForm);
      toast.success("Profile updated successfully");
    } catch {
      toast.error("Failed to update profile");
    }
  };

  const handleCreateApiKey = async () => {
    try {
      const result = await createApiKey.mutateAsync({
        name: apiKeyFormData.name,
        scopes: apiKeyFormData.scopes,
        expiresAt:
          apiKeyFormData.expiresIn !== "never"
            ? new Date(
                Date.now() + parseInt(apiKeyFormData.expiresIn) * 24 * 60 * 60 * 1000
              ).toISOString()
            : undefined,
      });
      setNewApiKey(result.key);
      toast.success("API key created successfully");
    } catch {
      toast.error("Failed to create API key");
    }
  };

  const handleDeleteApiKey = async () => {
    if (!selectedApiKey) return;
    try {
      await deleteApiKey.mutateAsync(selectedApiKey.id);
      toast.success("API key deleted successfully");
      setIsDeleteDialogOpen(false);
      setSelectedApiKey(null);
    } catch {
      toast.error("Failed to delete API key");
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success("Copied to clipboard");
  };

  const getInitials = (name?: string) => {
    if (!name) return "U";
    return name
      .split(" ")
      .map((n) => n[0])
      .join("")
      .toUpperCase()
      .slice(0, 2);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
        <p className="text-muted-foreground">
          Manage your account and application settings
        </p>
      </div>

      <Tabs defaultValue="profile" className="space-y-4">
        <TabsList>
          <TabsTrigger value="profile" className="flex items-center gap-2">
            <User className="h-4 w-4" />
            Profile
          </TabsTrigger>
          <TabsTrigger value="security" className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            Security
          </TabsTrigger>
          <TabsTrigger value="api-keys" className="flex items-center gap-2">
            <Key className="h-4 w-4" />
            API Keys
          </TabsTrigger>
          <TabsTrigger value="notifications" className="flex items-center gap-2">
            <Bell className="h-4 w-4" />
            Notifications
          </TabsTrigger>
          <TabsTrigger value="appearance" className="flex items-center gap-2">
            <Palette className="h-4 w-4" />
            Appearance
          </TabsTrigger>
        </TabsList>

        {/* Profile Tab */}
        <TabsContent value="profile" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Profile Information</CardTitle>
              <CardDescription>
                Update your account profile information
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {userLoading ? (
                <div className="space-y-4">
                  <Skeleton className="h-20 w-20 rounded-full" />
                  <Skeleton className="h-10 w-full" />
                  <Skeleton className="h-10 w-full" />
                </div>
              ) : (
                <>
                  <div className="flex items-center gap-6">
                    <Avatar className="h-20 w-20">
                      <AvatarImage src={user?.avatar} />
                      <AvatarFallback className="text-2xl">
                        {getInitials(user?.name)}
                      </AvatarFallback>
                    </Avatar>
                    <div>
                      <Button variant="outline" size="sm">
                        Change Avatar
                      </Button>
                      <p className="mt-1 text-xs text-muted-foreground">
                        JPG, PNG or GIF. Max size 2MB.
                      </p>
                    </div>
                  </div>
                  <Separator />
                  <div className="grid gap-4">
                    <div className="grid gap-2">
                      <Label htmlFor="name">Full Name</Label>
                      <Input
                        id="name"
                        value={profileForm.name}
                        onChange={(e) =>
                          setProfileForm({ ...profileForm, name: e.target.value })
                        }
                      />
                    </div>
                    <div className="grid gap-2">
                      <Label htmlFor="email">Email Address</Label>
                      <Input
                        id="email"
                        type="email"
                        value={profileForm.email}
                        onChange={(e) =>
                          setProfileForm({ ...profileForm, email: e.target.value })
                        }
                      />
                    </div>
                    <div className="grid gap-2">
                      <Label>Role</Label>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="capitalize">
                          {user?.role}
                        </Badge>
                        <span className="text-sm text-muted-foreground">
                          Member since {formatDate(user?.createdAt || "")}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="flex justify-end">
                    <Button
                      onClick={handleUpdateProfile}
                      disabled={updateUser.isPending}
                    >
                      {updateUser.isPending ? "Saving..." : "Save Changes"}
                    </Button>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Security Tab */}
        <TabsContent value="security" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Change Password</CardTitle>
              <CardDescription>
                Update your password to keep your account secure
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-2">
                <Label htmlFor="current-password">Current Password</Label>
                <Input id="current-password" type="password" />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="new-password">New Password</Label>
                <Input id="new-password" type="password" />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="confirm-password">Confirm New Password</Label>
                <Input id="confirm-password" type="password" />
              </div>
              <div className="flex justify-end">
                <Button>Update Password</Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Two-Factor Authentication</CardTitle>
              <CardDescription>
                Add an extra layer of security to your account
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Authenticator App</p>
                  <p className="text-sm text-muted-foreground">
                    Use an authenticator app to generate verification codes
                  </p>
                </div>
                <Button variant="outline">Enable</Button>
              </div>
            </CardContent>
          </Card>

          <Card className="border-destructive">
            <CardHeader>
              <CardTitle className="text-destructive">Danger Zone</CardTitle>
              <CardDescription>
                Irreversible and destructive actions
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Delete Account</p>
                  <p className="text-sm text-muted-foreground">
                    Permanently delete your account and all associated data
                  </p>
                </div>
                <Button variant="destructive">Delete Account</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* API Keys Tab */}
        <TabsContent value="api-keys" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>API Keys</CardTitle>
                  <CardDescription>
                    Manage your API keys for programmatic access
                  </CardDescription>
                </div>
                <Dialog
                  open={isApiKeyDialogOpen}
                  onOpenChange={(open) => {
                    setIsApiKeyDialogOpen(open);
                    if (!open) {
                      setNewApiKey(null);
                      setApiKeyFormData(defaultApiKeyFormData);
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
                    {newApiKey ? (
                      <>
                        <DialogHeader>
                          <DialogTitle>API Key Created</DialogTitle>
                          <DialogDescription>
                            Copy your new API key. You won't be able to see it again!
                          </DialogDescription>
                        </DialogHeader>
                        <div className="space-y-4 py-4">
                          <div className="flex items-center gap-2">
                            <Input
                              type={showNewKey ? "text" : "password"}
                              value={newApiKey}
                              readOnly
                              className="font-mono"
                            />
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => setShowNewKey(!showNewKey)}
                            >
                              {showNewKey ? (
                                <EyeOff className="h-4 w-4" />
                              ) : (
                                <Eye className="h-4 w-4" />
                              )}
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => copyToClipboard(newApiKey)}
                            >
                              <Copy className="h-4 w-4" />
                            </Button>
                          </div>
                        </div>
                        <DialogFooter>
                          <Button onClick={() => setIsApiKeyDialogOpen(false)}>
                            Done
                          </Button>
                        </DialogFooter>
                      </>
                    ) : (
                      <>
                        <DialogHeader>
                          <DialogTitle>Create API Key</DialogTitle>
                          <DialogDescription>
                            Create a new API key for programmatic access
                          </DialogDescription>
                        </DialogHeader>
                        <div className="space-y-4 py-4">
                          <div className="grid gap-2">
                            <Label htmlFor="key-name">Key Name</Label>
                            <Input
                              id="key-name"
                              placeholder="Production API Key"
                              value={apiKeyFormData.name}
                              onChange={(e) =>
                                setApiKeyFormData({
                                  ...apiKeyFormData,
                                  name: e.target.value,
                                })
                              }
                            />
                          </div>
                          <div className="grid gap-2">
                            <Label>Permissions</Label>
                            <div className="space-y-2">
                              <div className="flex items-center space-x-2">
                                <Checkbox
                                  id="read"
                                  checked={apiKeyFormData.scopes.includes("read")}
                                  onCheckedChange={(checked) => {
                                    if (checked) {
                                      setApiKeyFormData({
                                        ...apiKeyFormData,
                                        scopes: [...apiKeyFormData.scopes, "read"],
                                      });
                                    } else {
                                      setApiKeyFormData({
                                        ...apiKeyFormData,
                                        scopes: apiKeyFormData.scopes.filter(
                                          (s) => s !== "read"
                                        ),
                                      });
                                    }
                                  }}
                                />
                                <Label htmlFor="read">Read</Label>
                              </div>
                              <div className="flex items-center space-x-2">
                                <Checkbox
                                  id="write"
                                  checked={apiKeyFormData.scopes.includes("write")}
                                  onCheckedChange={(checked) => {
                                    if (checked) {
                                      setApiKeyFormData({
                                        ...apiKeyFormData,
                                        scopes: [...apiKeyFormData.scopes, "write"],
                                      });
                                    } else {
                                      setApiKeyFormData({
                                        ...apiKeyFormData,
                                        scopes: apiKeyFormData.scopes.filter(
                                          (s) => s !== "write"
                                        ),
                                      });
                                    }
                                  }}
                                />
                                <Label htmlFor="write">Write</Label>
                              </div>
                            </div>
                          </div>
                          <div className="grid gap-2">
                            <Label htmlFor="expires">Expiration</Label>
                            <Select
                              value={apiKeyFormData.expiresIn}
                              onValueChange={(value) =>
                                setApiKeyFormData({
                                  ...apiKeyFormData,
                                  expiresIn: value,
                                })
                              }
                            >
                              <SelectTrigger>
                                <SelectValue placeholder="Select expiration" />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="never">Never</SelectItem>
                                <SelectItem value="30">30 days</SelectItem>
                                <SelectItem value="90">90 days</SelectItem>
                                <SelectItem value="365">1 year</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                        </div>
                        <DialogFooter>
                          <Button
                            variant="outline"
                            onClick={() => setIsApiKeyDialogOpen(false)}
                          >
                            Cancel
                          </Button>
                          <Button
                            onClick={handleCreateApiKey}
                            disabled={createApiKey.isPending}
                          >
                            {createApiKey.isPending ? "Creating..." : "Create Key"}
                          </Button>
                        </DialogFooter>
                      </>
                    )}
                  </DialogContent>
                </Dialog>
              </div>
            </CardHeader>
            <CardContent>
              {apiKeysLoading ? (
                <div className="space-y-4">
                  {[1, 2].map((i) => (
                    <Skeleton key={i} className="h-16 w-full" />
                  ))}
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Key Prefix</TableHead>
                      <TableHead>Scopes</TableHead>
                      <TableHead>Last Used</TableHead>
                      <TableHead>Expires</TableHead>
                      <TableHead className="w-[70px]"></TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {apiKeys?.map((apiKey) => (
                      <TableRow key={apiKey.id}>
                        <TableCell className="font-medium">
                          {apiKey.name}
                        </TableCell>
                        <TableCell className="font-mono text-sm">
                          {apiKey.prefix}****
                        </TableCell>
                        <TableCell>
                          <div className="flex gap-1">
                            {apiKey.scopes.map((scope) => (
                              <Badge key={scope} variant="outline">
                                {scope}
                              </Badge>
                            ))}
                          </div>
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          {apiKey.lastUsed
                            ? formatDate(apiKey.lastUsed)
                            : "Never"}
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          {apiKey.expiresAt
                            ? formatDate(apiKey.expiresAt)
                            : "Never"}
                        </TableCell>
                        <TableCell>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="text-destructive hover:text-destructive"
                            onClick={() => {
                              setSelectedApiKey(apiKey);
                              setIsDeleteDialogOpen(true);
                            }}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          <AlertDialog
            open={isDeleteDialogOpen}
            onOpenChange={setIsDeleteDialogOpen}
          >
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Delete API Key</AlertDialogTitle>
                <AlertDialogDescription>
                  Are you sure you want to delete "{selectedApiKey?.name}"? Any
                  applications using this key will lose access.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction
                  onClick={handleDeleteApiKey}
                  className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                >
                  {deleteApiKey.isPending ? "Deleting..." : "Delete"}
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </TabsContent>

        {/* Notifications Tab */}
        <TabsContent value="notifications" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Email Notifications</CardTitle>
              <CardDescription>
                Configure how you receive notifications
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Email Notifications</p>
                  <p className="text-sm text-muted-foreground">
                    Receive email notifications for important events
                  </p>
                </div>
                <Switch
                  checked={notifications.email}
                  onCheckedChange={(checked) =>
                    setNotifications({ ...notifications, email: checked })
                  }
                />
              </div>
              <Separator />
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Attack Alerts</p>
                  <p className="text-sm text-muted-foreground">
                    Get notified when attacks are detected and blocked
                  </p>
                </div>
                <Switch
                  checked={notifications.attacks}
                  onCheckedChange={(checked) =>
                    setNotifications({ ...notifications, attacks: checked })
                  }
                />
              </div>
              <Separator />
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Usage Alerts</p>
                  <p className="text-sm text-muted-foreground">
                    Get notified when approaching usage limits
                  </p>
                </div>
                <Switch
                  checked={notifications.usage}
                  onCheckedChange={(checked) =>
                    setNotifications({ ...notifications, usage: checked })
                  }
                />
              </div>
              <Separator />
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Newsletter</p>
                  <p className="text-sm text-muted-foreground">
                    Receive product updates and news
                  </p>
                </div>
                <Switch
                  checked={notifications.newsletter}
                  onCheckedChange={(checked) =>
                    setNotifications({ ...notifications, newsletter: checked })
                  }
                />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Appearance Tab */}
        <TabsContent value="appearance" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Theme</CardTitle>
              <CardDescription>
                Customize the appearance of the application
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-3 gap-4">
                <Button
                  variant="outline"
                  className="h-24 flex-col gap-2"
                  onClick={() => {
                    document.documentElement.classList.remove("dark");
                    localStorage.setItem("theme", "light");
                  }}
                >
                  <div className="h-8 w-8 rounded-full bg-white border" />
                  <span>Light</span>
                </Button>
                <Button
                  variant="outline"
                  className="h-24 flex-col gap-2"
                  onClick={() => {
                    document.documentElement.classList.add("dark");
                    localStorage.setItem("theme", "dark");
                  }}
                >
                  <div className="h-8 w-8 rounded-full bg-zinc-900 border" />
                  <span>Dark</span>
                </Button>
                <Button
                  variant="outline"
                  className="h-24 flex-col gap-2"
                  onClick={() => {
                    const prefersDark = window.matchMedia(
                      "(prefers-color-scheme: dark)"
                    ).matches;
                    document.documentElement.classList.toggle("dark", prefersDark);
                    localStorage.removeItem("theme");
                  }}
                >
                  <RefreshCw className="h-8 w-8" />
                  <span>System</span>
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
