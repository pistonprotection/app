import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import {
  AlertTriangle,
  Bell,
  Check,
  Database,
  Globe,
  Key,
  Lock,
  Mail,
  RefreshCw,
  Save,
  Server,
  Settings,
  Shield,
  Webhook,
  Zap,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

export const Route = createFileRoute("/admin/settings")({
  component: AdminSettingsPage,
});

function AdminSettingsPage() {
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const handleSave = async () => {
    setSaving(true);
    // Simulate API call
    await new Promise((resolve) => setTimeout(resolve, 1000));
    setSaving(false);
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Platform Settings</h1>
          <p className="text-muted-foreground">
            Configure global platform settings and integrations
          </p>
        </div>
        <Button onClick={handleSave} disabled={saving}>
          {saving ? (
            <>
              <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
              Saving...
            </>
          ) : saved ? (
            <>
              <Check className="h-4 w-4 mr-2" />
              Saved
            </>
          ) : (
            <>
              <Save className="h-4 w-4 mr-2" />
              Save Changes
            </>
          )}
        </Button>
      </div>

      <Tabs defaultValue="general">
        <TabsList className="grid grid-cols-6 w-full max-w-3xl">
          <TabsTrigger value="general">General</TabsTrigger>
          <TabsTrigger value="security">Security</TabsTrigger>
          <TabsTrigger value="email">Email</TabsTrigger>
          <TabsTrigger value="billing">Billing</TabsTrigger>
          <TabsTrigger value="integrations">Integrations</TabsTrigger>
          <TabsTrigger value="advanced">Advanced</TabsTrigger>
        </TabsList>

        <TabsContent value="general" className="space-y-6 mt-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Globe className="h-5 w-5" />
                Platform Information
              </CardTitle>
              <CardDescription>Basic platform configuration</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="platform-name">Platform Name</Label>
                  <Input id="platform-name" defaultValue="PistonProtection" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="platform-url">Platform URL</Label>
                  <Input
                    id="platform-url"
                    defaultValue="https://pistonprotection.com"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="support-email">Support Email</Label>
                  <Input
                    id="support-email"
                    type="email"
                    defaultValue="support@pistonprotection.com"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="status-page">Status Page URL</Label>
                  <Input
                    id="status-page"
                    defaultValue="https://status.pistonprotection.com"
                  />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Default Limits</CardTitle>
              <CardDescription>Default resource limits for new organizations</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-3">
                <div className="space-y-2">
                  <Label htmlFor="default-backends">Max Backends</Label>
                  <Input id="default-backends" type="number" defaultValue="3" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="default-domains">Max Domains</Label>
                  <Input id="default-domains" type="number" defaultValue="5" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="default-rules">Max Filter Rules</Label>
                  <Input id="default-rules" type="number" defaultValue="10" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Maintenance Mode</CardTitle>
              <CardDescription>
                Enable maintenance mode to block all non-admin access
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="font-medium">Enable Maintenance Mode</p>
                  <p className="text-sm text-muted-foreground">
                    Only administrators will be able to access the platform
                  </p>
                </div>
                <Switch />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security" className="space-y-6 mt-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Lock className="h-5 w-5" />
                Authentication Settings
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="font-medium">Require Two-Factor Authentication</p>
                  <p className="text-sm text-muted-foreground">
                    Force all users to enable 2FA
                  </p>
                </div>
                <Switch />
              </div>
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="font-medium">Allow Password Login</p>
                  <p className="text-sm text-muted-foreground">
                    Allow users to login with email and password
                  </p>
                </div>
                <Switch defaultChecked />
              </div>
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="font-medium">Allow OAuth Login</p>
                  <p className="text-sm text-muted-foreground">
                    Allow users to login with Google, GitHub, etc.
                  </p>
                </div>
                <Switch defaultChecked />
              </div>
              <div className="space-y-2">
                <Label htmlFor="session-timeout">Session Timeout (hours)</Label>
                <Input id="session-timeout" type="number" defaultValue="24" className="w-32" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Key className="h-5 w-5" />
                API Security
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="font-medium">Rate Limiting</p>
                  <p className="text-sm text-muted-foreground">
                    Enable API rate limiting for all endpoints
                  </p>
                </div>
                <Switch defaultChecked />
              </div>
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="rate-limit">Requests per Minute</Label>
                  <Input id="rate-limit" type="number" defaultValue="1000" />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="burst-limit">Burst Limit</Label>
                  <Input id="burst-limit" type="number" defaultValue="100" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5" />
                IP Restrictions
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="admin-ips">Admin IP Whitelist</Label>
                <Textarea
                  id="admin-ips"
                  placeholder="Enter one IP or CIDR per line"
                  className="font-mono"
                  rows={4}
                />
                <p className="text-xs text-muted-foreground">
                  Leave empty to allow access from any IP
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="email" className="space-y-6 mt-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Mail className="h-5 w-5" />
                Email Provider
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>Email Provider</Label>
                <Select defaultValue="resend">
                  <SelectTrigger className="w-[200px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="resend">Resend</SelectItem>
                    <SelectItem value="smtp">SMTP</SelectItem>
                    <SelectItem value="disabled">Disabled</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="resend-key">Resend API Key</Label>
                <Input
                  id="resend-key"
                  type="password"
                  placeholder="re_..."
                  defaultValue="••••••••••••••••"
                />
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="from-email">From Email</Label>
                  <Input
                    id="from-email"
                    type="email"
                    defaultValue="noreply@pistonprotection.com"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="from-name">From Name</Label>
                  <Input id="from-name" defaultValue="PistonProtection" />
                </div>
              </div>

              <Button variant="outline">
                <Mail className="h-4 w-4 mr-2" />
                Send Test Email
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Bell className="h-5 w-5" />
                Email Notifications
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {[
                { label: "New user registration", enabled: true },
                { label: "Subscription changes", enabled: true },
                { label: "Payment failures", enabled: true },
                { label: "Attack alerts", enabled: true },
                { label: "Weekly usage reports", enabled: false },
              ].map((item) => (
                <div key={item.label} className="flex items-center justify-between">
                  <span>{item.label}</span>
                  <Switch defaultChecked={item.enabled} />
                </div>
              ))}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="billing" className="space-y-6 mt-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Zap className="h-5 w-5" />
                Stripe Configuration
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-2 mb-4">
                <Badge variant="default">Connected</Badge>
                <span className="text-sm text-muted-foreground">
                  Account: acct_1234567890
                </span>
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="stripe-pk">Publishable Key</Label>
                  <Input
                    id="stripe-pk"
                    type="password"
                    defaultValue="••••••••••••••••"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="stripe-sk">Secret Key</Label>
                  <Input
                    id="stripe-sk"
                    type="password"
                    defaultValue="••••••••••••••••"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="stripe-webhook">Webhook Secret</Label>
                <Input
                  id="stripe-webhook"
                  type="password"
                  defaultValue="••••••••••••••••"
                />
              </div>

              <div className="flex items-center justify-between pt-4">
                <div className="space-y-1">
                  <p className="font-medium">Test Mode</p>
                  <p className="text-sm text-muted-foreground">
                    Use Stripe test environment
                  </p>
                </div>
                <Switch />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Billing Settings</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="font-medium">Free Trial</p>
                  <p className="text-sm text-muted-foreground">
                    Enable free trial for new organizations
                  </p>
                </div>
                <Switch defaultChecked />
              </div>
              <div className="space-y-2">
                <Label htmlFor="trial-days">Trial Duration (days)</Label>
                <Input id="trial-days" type="number" defaultValue="14" className="w-32" />
              </div>
              <div className="flex items-center justify-between">
                <div className="space-y-1">
                  <p className="font-medium">Require Payment Method for Trial</p>
                  <p className="text-sm text-muted-foreground">
                    Require credit card before starting trial
                  </p>
                </div>
                <Switch />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="integrations" className="space-y-6 mt-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Webhook className="h-5 w-5" />
                Webhooks
              </CardTitle>
              <CardDescription>
                Configure outgoing webhooks for platform events
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="rounded-lg border p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-medium">Attack Notifications</p>
                    <p className="text-sm text-muted-foreground font-mono">
                      https://hooks.slack.com/...
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="default">Active</Badge>
                    <Button variant="ghost" size="sm">Edit</Button>
                  </div>
                </div>
              </div>

              <Button variant="outline">
                <Webhook className="h-4 w-4 mr-2" />
                Add Webhook
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>External Services</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {[
                {
                  name: "Grafana",
                  status: "connected",
                  url: "https://grafana.pistonprotection.com",
                },
                {
                  name: "Prometheus",
                  status: "connected",
                  url: "https://prometheus.pistonprotection.com",
                },
                {
                  name: "Loki",
                  status: "connected",
                  url: "https://loki.pistonprotection.com",
                },
                {
                  name: "Sentry",
                  status: "not_configured",
                  url: null,
                },
              ].map((service) => (
                <div key={service.name} className="flex items-center justify-between p-4 rounded-lg border">
                  <div>
                    <p className="font-medium">{service.name}</p>
                    {service.url && (
                      <p className="text-sm text-muted-foreground">{service.url}</p>
                    )}
                  </div>
                  <Badge
                    variant={service.status === "connected" ? "default" : "secondary"}
                  >
                    {service.status === "connected" ? "Connected" : "Not Configured"}
                  </Badge>
                </div>
              ))}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="advanced" className="space-y-6 mt-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Database className="h-5 w-5" />
                Database
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between p-4 rounded-lg border">
                <div>
                  <p className="font-medium">PostgreSQL</p>
                  <p className="text-sm text-muted-foreground">Primary database</p>
                </div>
                <Badge variant="default">Connected</Badge>
              </div>
              <div className="flex items-center justify-between p-4 rounded-lg border">
                <div>
                  <p className="font-medium">Redis</p>
                  <p className="text-sm text-muted-foreground">Cache and sessions</p>
                </div>
                <Badge variant="default">Connected</Badge>
              </div>
            </CardContent>
          </Card>

          <Card className="border-red-200 dark:border-red-900">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-red-600">
                <AlertTriangle className="h-5 w-5" />
                Danger Zone
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between p-4 rounded-lg border border-red-200 dark:border-red-900">
                <div>
                  <p className="font-medium">Purge All Cache</p>
                  <p className="text-sm text-muted-foreground">
                    Clear all cached data from Redis
                  </p>
                </div>
                <Dialog>
                  <DialogTrigger asChild>
                    <Button variant="destructive" size="sm">Purge Cache</Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>Purge All Cache?</DialogTitle>
                      <DialogDescription>
                        This will clear all cached data. This action cannot be undone
                        and may temporarily affect performance.
                      </DialogDescription>
                    </DialogHeader>
                    <DialogFooter>
                      <Button variant="outline">Cancel</Button>
                      <Button variant="destructive">Purge Cache</Button>
                    </DialogFooter>
                  </DialogContent>
                </Dialog>
              </div>

              <div className="flex items-center justify-between p-4 rounded-lg border border-red-200 dark:border-red-900">
                <div>
                  <p className="font-medium">Reset All Rate Limits</p>
                  <p className="text-sm text-muted-foreground">
                    Clear all rate limiting counters
                  </p>
                </div>
                <Button variant="destructive" size="sm">Reset Limits</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
