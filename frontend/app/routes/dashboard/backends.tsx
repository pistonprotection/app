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
import { Switch } from "@/components/ui/switch";
import {
  Server,
  Plus,
  Settings,
  Trash2,
  ExternalLink,
  Activity,
  Shield,
  Globe,
} from "lucide-react";

export const Route = createFileRoute("/dashboard/backends")({
  component: BackendsPage,
});

const backends = [
  {
    id: "1",
    name: "mc.example.com",
    address: "192.168.1.100:25565",
    protocol: "minecraft-java",
    status: "healthy",
    enabled: true,
    stats: {
      requests: "1.2M",
      blocked: "45K",
      latency: "12ms",
    },
  },
  {
    id: "2",
    name: "web.example.com",
    address: "192.168.1.101:443",
    protocol: "https",
    status: "healthy",
    enabled: true,
    stats: {
      requests: "3.5M",
      blocked: "120K",
      latency: "8ms",
    },
  },
  {
    id: "3",
    name: "api.example.com",
    address: "192.168.1.102:8080",
    protocol: "http",
    status: "degraded",
    enabled: true,
    stats: {
      requests: "890K",
      blocked: "23K",
      latency: "45ms",
    },
  },
  {
    id: "4",
    name: "game.example.com",
    address: "192.168.1.103:19132",
    protocol: "minecraft-bedrock",
    status: "offline",
    enabled: false,
    stats: {
      requests: "0",
      blocked: "0",
      latency: "-",
    },
  },
];

function BackendsPage() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Backends</h1>
          <p className="text-muted-foreground">
            Manage your protected backend servers
          </p>
        </div>
        <Dialog>
          <DialogTrigger asChild>
            <Button className="gap-2">
              <Plus className="h-4 w-4" />
              Add Backend
            </Button>
          </DialogTrigger>
          <DialogContent className="sm:max-w-[500px]">
            <DialogHeader>
              <DialogTitle>Add New Backend</DialogTitle>
              <DialogDescription>
                Configure a new backend server for DDoS protection
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="grid gap-2">
                <Label htmlFor="name">Domain Name</Label>
                <Input
                  id="name"
                  placeholder="mc.example.com"
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="address">Backend Address</Label>
                <Input
                  id="address"
                  placeholder="192.168.1.100:25565"
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="protocol">Protocol</Label>
                <Select defaultValue="minecraft-java">
                  <SelectTrigger>
                    <SelectValue placeholder="Select protocol" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="minecraft-java">Minecraft Java</SelectItem>
                    <SelectItem value="minecraft-bedrock">Minecraft Bedrock</SelectItem>
                    <SelectItem value="https">HTTPS</SelectItem>
                    <SelectItem value="http">HTTP</SelectItem>
                    <SelectItem value="tcp">TCP</SelectItem>
                    <SelectItem value="udp">UDP</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Enable Protection</Label>
                  <p className="text-sm text-muted-foreground">
                    Start protecting immediately after creation
                  </p>
                </div>
                <Switch defaultChecked />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline">Cancel</Button>
              <Button>Create Backend</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Stats Overview */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Backends</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">4</div>
            <p className="text-xs text-muted-foreground">3 active, 1 offline</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Traffic</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">5.6M</div>
            <p className="text-xs text-muted-foreground">requests today</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Blocked</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">188K</div>
            <p className="text-xs text-muted-foreground">malicious requests</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Regions</CardTitle>
            <Globe className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">3</div>
            <p className="text-xs text-muted-foreground">active PoPs</p>
          </CardContent>
        </Card>
      </div>

      {/* Backend List */}
      <div className="space-y-4">
        {backends.map((backend) => (
          <Card key={backend.id}>
            <CardContent className="p-6">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div
                    className={`h-10 w-10 rounded-lg flex items-center justify-center ${
                      backend.status === "healthy"
                        ? "bg-success/20"
                        : backend.status === "degraded"
                        ? "bg-warning/20"
                        : "bg-muted"
                    }`}
                  >
                    <Server
                      className={`h-5 w-5 ${
                        backend.status === "healthy"
                          ? "text-success"
                          : backend.status === "degraded"
                          ? "text-warning"
                          : "text-muted-foreground"
                      }`}
                    />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold">{backend.name}</h3>
                      <Badge
                        variant={
                          backend.status === "healthy"
                            ? "success"
                            : backend.status === "degraded"
                            ? "warning"
                            : "destructive"
                        }
                      >
                        {backend.status}
                      </Badge>
                      <Badge variant="outline">{backend.protocol}</Badge>
                    </div>
                    <p className="text-sm text-muted-foreground">
                      {backend.address}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-6">
                  {/* Stats */}
                  <div className="hidden md:flex items-center gap-6 text-sm">
                    <div className="text-center">
                      <p className="font-medium">{backend.stats.requests}</p>
                      <p className="text-xs text-muted-foreground">requests</p>
                    </div>
                    <div className="text-center">
                      <p className="font-medium">{backend.stats.blocked}</p>
                      <p className="text-xs text-muted-foreground">blocked</p>
                    </div>
                    <div className="text-center">
                      <p className="font-medium">{backend.stats.latency}</p>
                      <p className="text-xs text-muted-foreground">latency</p>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2">
                    <Switch checked={backend.enabled} />
                    <Button variant="ghost" size="icon">
                      <ExternalLink className="h-4 w-4" />
                    </Button>
                    <Button variant="ghost" size="icon">
                      <Settings className="h-4 w-4" />
                    </Button>
                    <Button variant="ghost" size="icon" className="text-destructive">
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
