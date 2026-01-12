import { createFileRoute } from "@tanstack/react-router"
import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Separator } from "@/components/ui/separator"
import { Badge } from "@/components/ui/badge"
import { Settings, Shield, Bell, Key, Globe } from "lucide-react"

export const Route = createFileRoute("/dashboard/settings")({ component: SettingsPage })

function SettingsPage() {
  const [emailNotifications, setEmailNotifications] = useState(true)
  const [slackNotifications, setSlackNotifications] = useState(false)
  const [autoMitigation, setAutoMitigation] = useState(true)
  const [challengeMode, setChallengeMode] = useState(true)
  return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">Settings</h1><p className="text-muted-foreground">Configure your protection preferences and account settings.</p></div>
      <Tabs defaultValue="general" className="space-y-4">
        <TabsList><TabsTrigger value="general"><Settings className="mr-2 h-4 w-4" />General</TabsTrigger><TabsTrigger value="security"><Shield className="mr-2 h-4 w-4" />Security</TabsTrigger><TabsTrigger value="notifications"><Bell className="mr-2 h-4 w-4" />Notifications</TabsTrigger><TabsTrigger value="api"><Key className="mr-2 h-4 w-4" />API</TabsTrigger></TabsList>
        <TabsContent value="general" className="space-y-4">
          <Card>
            <CardHeader><CardTitle>Organization Settings</CardTitle><CardDescription>Manage your organization details.</CardDescription></CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-2"><Label>Organization Name</Label><Input defaultValue="Acme Corporation" /></div>
              <div className="grid gap-2"><Label>Contact Email</Label><Input type="email" defaultValue="admin@acme.com" /></div>
              <div className="grid grid-cols-2 gap-4"><div className="grid gap-2"><Label>Timezone</Label><Select defaultValue="utc"><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="utc">UTC</SelectItem><SelectItem value="est">Eastern Time</SelectItem><SelectItem value="pst">Pacific Time</SelectItem><SelectItem value="cet">Central European</SelectItem></SelectContent></Select></div><div className="grid gap-2"><Label>Date Format</Label><Select defaultValue="iso"><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="iso">YYYY-MM-DD</SelectItem><SelectItem value="us">MM/DD/YYYY</SelectItem><SelectItem value="eu">DD/MM/YYYY</SelectItem></SelectContent></Select></div></div>
              <Button>Save Changes</Button>
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="security" className="space-y-4">
          <Card>
            <CardHeader><CardTitle>Protection Settings</CardTitle><CardDescription>Configure automatic protection behavior.</CardDescription></CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between"><div className="space-y-0.5"><Label className="text-base">Auto Mitigation</Label><p className="text-sm text-muted-foreground">Automatically apply mitigation when attacks are detected.</p></div><Switch checked={autoMitigation} onCheckedChange={setAutoMitigation} /></div>
              <Separator />
              <div className="flex items-center justify-between"><div className="space-y-0.5"><Label className="text-base">Challenge Mode</Label><p className="text-sm text-muted-foreground">Present challenges to suspicious traffic before blocking.</p></div><Switch checked={challengeMode} onCheckedChange={setChallengeMode} /></div>
              <Separator />
              <div className="grid gap-2"><Label>Sensitivity Level</Label><Select defaultValue="medium"><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="low">Low - Fewer false positives</SelectItem><SelectItem value="medium">Medium - Balanced</SelectItem><SelectItem value="high">High - Maximum protection</SelectItem></SelectContent></Select></div>
              <Button>Update Security Settings</Button>
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>IP Allowlist</CardTitle><CardDescription>IPs that bypass all protection filters.</CardDescription></CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-2"><Input placeholder="Enter IP address or CIDR range" /><Button>Add</Button></div>
              <div className="space-y-2">{["10.0.0.0/8", "192.168.1.0/24", "203.0.113.50"].map((ip, i) => (<div key={i} className="flex items-center justify-between p-2 rounded border"><span className="font-mono text-sm">{ip}</span><Button variant="ghost" size="sm" className="text-destructive">Remove</Button></div>))}</div>
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="notifications" className="space-y-4">
          <Card>
            <CardHeader><CardTitle>Notification Channels</CardTitle><CardDescription>Configure how you receive alerts.</CardDescription></CardHeader>
            <CardContent className="space-y-6">
              <div className="flex items-center justify-between"><div className="flex items-center gap-3"><Bell className="h-5 w-5 text-muted-foreground" /><div><Label className="text-base">Email Notifications</Label><p className="text-sm text-muted-foreground">Receive alerts via email.</p></div></div><Switch checked={emailNotifications} onCheckedChange={setEmailNotifications} /></div>
              {emailNotifications && (<div className="ml-8 grid gap-2"><Label>Email Address</Label><Input type="email" defaultValue="alerts@acme.com" /></div>)}
              <Separator />
              <div className="flex items-center justify-between"><div className="flex items-center gap-3"><Globe className="h-5 w-5 text-muted-foreground" /><div><Label className="text-base">Slack Notifications</Label><p className="text-sm text-muted-foreground">Send alerts to Slack channel.</p></div></div><Switch checked={slackNotifications} onCheckedChange={setSlackNotifications} /></div>
              {slackNotifications && (<div className="ml-8 grid gap-2"><Label>Webhook URL</Label><Input placeholder="https://hooks.slack.com/services/..." /></div>)}
              <Button>Save Notification Settings</Button>
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="api" className="space-y-4">
          <Card>
            <CardHeader><CardTitle>API Keys</CardTitle><CardDescription>Manage API keys for programmatic access.</CardDescription></CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between p-4 rounded border"><div className="space-y-1"><div className="flex items-center gap-2"><span className="font-medium">Production Key</span><Badge>Active</Badge></div><code className="text-sm text-muted-foreground">pp_live_****************************a1b2</code></div><div className="flex gap-2"><Button variant="outline" size="sm">Reveal</Button><Button variant="outline" size="sm">Regenerate</Button></div></div>
              <div className="flex items-center justify-between p-4 rounded border"><div className="space-y-1"><div className="flex items-center gap-2"><span className="font-medium">Test Key</span><Badge variant="secondary">Test</Badge></div><code className="text-sm text-muted-foreground">pp_test_****************************c3d4</code></div><div className="flex gap-2"><Button variant="outline" size="sm">Reveal</Button><Button variant="outline" size="sm">Regenerate</Button></div></div>
              <Button><Key className="mr-2 h-4 w-4" />Create New API Key</Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
