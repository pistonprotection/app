import { createFileRoute } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import {
  Filter,
  Plus,
  Pencil,
  Trash2,
  Shield,
  Ban,
  Check,
  Clock,
  Globe,
  Zap,
} from "lucide-react";

export const Route = createFileRoute("/dashboard/filters")({
  component: FiltersPage,
});

const filterRules = [
  {
    id: "1",
    name: "Block Known Botnets",
    type: "ip_blocklist",
    action: "drop",
    priority: 100,
    enabled: true,
    matches: "45.2K",
  },
  {
    id: "2",
    name: "SYN Flood Protection",
    type: "syn_flood",
    action: "ratelimit",
    priority: 90,
    enabled: true,
    matches: "12.8K",
  },
  {
    id: "3",
    name: "Minecraft Invalid Packets",
    type: "protocol",
    action: "drop",
    priority: 80,
    enabled: true,
    matches: "8.3K",
  },
  {
    id: "4",
    name: "Geographic Block (CN)",
    type: "geo",
    action: "drop",
    priority: 70,
    enabled: false,
    matches: "0",
  },
  {
    id: "5",
    name: "UDP Amplification",
    type: "udp_amp",
    action: "drop",
    priority: 85,
    enabled: true,
    matches: "23.1K",
  },
];

const ipBlocklist = [
  { ip: "185.220.101.0/24", reason: "Known Tor exit nodes", addedAt: "2024-01-15" },
  { ip: "45.155.205.0/24", reason: "DDoS source network", addedAt: "2024-01-10" },
  { ip: "192.168.100.50", reason: "Manual block - abuse", addedAt: "2024-01-08" },
];

const ipAllowlist = [
  { ip: "10.0.0.0/8", reason: "Internal network", addedAt: "2024-01-01" },
  { ip: "172.16.0.0/12", reason: "Private network", addedAt: "2024-01-01" },
];

function FiltersPage() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Filter Rules</h1>
          <p className="text-muted-foreground">
            Configure DDoS mitigation and traffic filtering rules
          </p>
        </div>
        <Dialog>
          <DialogTrigger asChild>
            <Button className="gap-2">
              <Plus className="h-4 w-4" />
              Add Rule
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-[500px]">
            <DialogHeader>
              <DialogTitle>Create Filter Rule</DialogTitle>
              <DialogDescription>
                Add a new traffic filtering rule
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="grid gap-2">
                <Label htmlFor="ruleName">Rule Name</Label>
                <Input id="ruleName" placeholder="My Custom Rule" />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="ruleType">Rule Type</Label>
                <Select>
                  <SelectTrigger>
                    <SelectValue placeholder="Select type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ip_blocklist">IP Blocklist</SelectItem>
                    <SelectItem value="syn_flood">SYN Flood Protection</SelectItem>
                    <SelectItem value="udp_amp">UDP Amplification</SelectItem>
                    <SelectItem value="protocol">Protocol Validation</SelectItem>
                    <SelectItem value="geo">Geographic Filter</SelectItem>
                    <SelectItem value="ratelimit">Rate Limit</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="action">Action</Label>
                <Select>
                  <SelectTrigger>
                    <SelectValue placeholder="Select action" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="drop">Drop</SelectItem>
                    <SelectItem value="ratelimit">Rate Limit</SelectItem>
                    <SelectItem value="allow">Allow</SelectItem>
                    <SelectItem value="log">Log Only</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="priority">Priority (1-100)</Label>
                <Input id="priority" type="number" min="1" max="100" defaultValue="50" />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline">Cancel</Button>
              <Button>Create Rule</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Rules</CardTitle>
            <Filter className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">4</div>
            <p className="text-xs text-muted-foreground">of 5 total</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Blocked IPs</CardTitle>
            <Ban className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">1,247</div>
            <p className="text-xs text-muted-foreground">in blocklist</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Matches Today</CardTitle>
            <Zap className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">89.4K</div>
            <p className="text-xs text-muted-foreground">packets filtered</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Allowed IPs</CardTitle>
            <Check className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">24</div>
            <p className="text-xs text-muted-foreground">in allowlist</p>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="rules" className="space-y-4">
        <TabsList>
          <TabsTrigger value="rules">Filter Rules</TabsTrigger>
          <TabsTrigger value="blocklist">IP Blocklist</TabsTrigger>
          <TabsTrigger value="allowlist">IP Allowlist</TabsTrigger>
        </TabsList>

        <TabsContent value="rules" className="space-y-4">
          {filterRules.map((rule) => (
            <Card key={rule.id}>
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center">
                      <Filter className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="font-medium">{rule.name}</h3>
                        <Badge variant="outline">{rule.type}</Badge>
                        <Badge
                          variant={
                            rule.action === "drop"
                              ? "destructive"
                              : rule.action === "ratelimit"
                              ? "warning"
                              : "success"
                          }
                        >
                          {rule.action}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground">
                        Priority: {rule.priority} • {rule.matches} matches
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Switch checked={rule.enabled} />
                    <Button variant="ghost" size="icon">
                      <Pencil className="h-4 w-4" />
                    </Button>
                    <Button variant="ghost" size="icon" className="text-destructive">
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        <TabsContent value="blocklist" className="space-y-4">
          <div className="flex justify-between items-center">
            <Input placeholder="Search IPs..." className="max-w-sm" />
            <Button className="gap-2">
              <Plus className="h-4 w-4" />
              Add IP
            </Button>
          </div>
          <Card>
            <CardContent className="p-0">
              <div className="divide-y">
                {ipBlocklist.map((entry, i) => (
                  <div key={i} className="flex items-center justify-between p-4">
                    <div className="flex items-center gap-4">
                      <div className="h-8 w-8 rounded bg-destructive/10 flex items-center justify-center">
                        <Ban className="h-4 w-4 text-destructive" />
                      </div>
                      <div>
                        <p className="font-mono font-medium">{entry.ip}</p>
                        <p className="text-sm text-muted-foreground">{entry.reason}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <span className="text-sm text-muted-foreground">
                        Added {entry.addedAt}
                      </span>
                      <Button variant="ghost" size="icon" className="text-destructive">
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="allowlist" className="space-y-4">
          <div className="flex justify-between items-center">
            <Input placeholder="Search IPs..." className="max-w-sm" />
            <Button className="gap-2">
              <Plus className="h-4 w-4" />
              Add IP
            </Button>
          </div>
          <Card>
            <CardContent className="p-0">
              <div className="divide-y">
                {ipAllowlist.map((entry, i) => (
                  <div key={i} className="flex items-center justify-between p-4">
                    <div className="flex items-center gap-4">
                      <div className="h-8 w-8 rounded bg-success/10 flex items-center justify-center">
                        <Check className="h-4 w-4 text-success" />
                      </div>
                      <div>
                        <p className="font-mono font-medium">{entry.ip}</p>
                        <p className="text-sm text-muted-foreground">{entry.reason}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <span className="text-sm text-muted-foreground">
                        Added {entry.addedAt}
                      </span>
                      <Button variant="ghost" size="icon" className="text-destructive">
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
