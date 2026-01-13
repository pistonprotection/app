// @ts-nocheck
// TODO: API response structure differs from expected (backends array, limit param, etc.)
import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  ArrowRight,
  CheckCircle2,
  Circle,
  ClipboardCopy,
  ExternalLink,
  Globe,
  Loader2,
  Server,
  Shield,
  Terminal,
  Zap,
} from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useOrganizationId } from "@/hooks/use-organization";
import { useTRPC } from "@/lib/trpc/client";

export const Route = createFileRoute("/dashboard/setup")({
  component: SetupPage,
});

function SetupPage() {
  const trpc = useTRPC();
  const organizationId = useOrganizationId();
  const [selectedBackend, setSelectedBackend] = useState<string | null>(null);

  // Fetch backends
  const { data: backends, isLoading: backendsLoading } = useQuery(
    trpc.backends.list.queryOptions({
      organizationId,
      limit: 100,
    }),
  );

  // Check setup completion status
  const hasBackends = (backends?.backends?.length ?? 0) > 0;
  const { data: filters } = useQuery(
    trpc.filters.list.queryOptions({
      organizationId,
      limit: 1,
    }),
  );
  const hasFilters = (filters?.filters?.length ?? 0) > 0;

  const steps = [
    {
      id: 1,
      title: "Create Your First Backend",
      description: "Configure a backend endpoint to protect",
      completed: hasBackends,
      link: "/dashboard/backends",
    },
    {
      id: 2,
      title: "Configure Filter Rules",
      description: "Set up protection rules for your traffic",
      completed: hasFilters,
      link: "/dashboard/filters",
    },
    {
      id: 3,
      title: "Update DNS Records",
      description: "Point your domain to PistonProtection",
      completed: false,
      link: null,
    },
  ];

  const completedSteps = steps.filter((s) => s.completed).length;

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard`);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Setup Guide</h1>
        <p className="text-muted-foreground">
          Follow these steps to get your DDoS protection up and running.
        </p>
      </div>

      {/* Progress Overview */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="h-5 w-5 text-primary" />
            Quick Setup Progress
          </CardTitle>
          <CardDescription>
            Complete these steps to activate your protection
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            {steps.map((step) => (
              <div
                key={step.id}
                className={`flex items-start gap-3 rounded-lg border p-4 ${
                  step.completed
                    ? "border-green-500 bg-green-500/5"
                    : "border-border"
                }`}
              >
                {step.completed ? (
                  <CheckCircle2 className="h-5 w-5 text-green-500 shrink-0 mt-0.5" />
                ) : (
                  <Circle className="h-5 w-5 text-muted-foreground shrink-0 mt-0.5" />
                )}
                <div className="space-y-1">
                  <p className="font-medium text-sm">{step.title}</p>
                  <p className="text-xs text-muted-foreground">
                    {step.description}
                  </p>
                  {!step.completed && step.link && (
                    <Link to={step.link}>
                      <Button variant="link" className="h-auto p-0 text-xs">
                        Get started <ArrowRight className="h-3 w-3 ml-1" />
                      </Button>
                    </Link>
                  )}
                </div>
              </div>
            ))}
          </div>
          <div className="mt-4 flex items-center gap-2">
            <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
              <div
                className="h-full bg-primary transition-all"
                style={{
                  width: `${(completedSteps / steps.length) * 100}%`,
                }}
              />
            </div>
            <span className="text-sm text-muted-foreground">
              {completedSteps}/{steps.length} complete
            </span>
          </div>
        </CardContent>
      </Card>

      {/* DNS Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Globe className="h-5 w-5" />
            DNS Configuration
          </CardTitle>
          <CardDescription>
            Point your domain to PistonProtection to route traffic through our
            network
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {backendsLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : backends?.backends && backends.backends.length > 0 ? (
            <>
              <div className="flex items-center gap-4">
                <span className="text-sm font-medium">Select Backend:</span>
                <Select
                  value={selectedBackend ?? backends.backends[0]?.id}
                  onValueChange={setSelectedBackend}
                >
                  <SelectTrigger className="w-[250px]">
                    <SelectValue placeholder="Select a backend" />
                  </SelectTrigger>
                  <SelectContent>
                    {backends.backends.map((backend) => (
                      <SelectItem key={backend.id} value={backend.id}>
                        {backend.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <Separator />

              <div className="space-y-4">
                <h4 className="font-medium">Required DNS Records</h4>

                <Tabs defaultValue="a-record" className="w-full">
                  <TabsList>
                    <TabsTrigger value="a-record">A Record</TabsTrigger>
                    <TabsTrigger value="cname">CNAME</TabsTrigger>
                    <TabsTrigger value="srv">SRV (Minecraft)</TabsTrigger>
                  </TabsList>

                  <TabsContent value="a-record" className="space-y-4">
                    <Alert>
                      <Terminal className="h-4 w-4" />
                      <AlertTitle>A Record Configuration</AlertTitle>
                      <AlertDescription>
                        Point your domain directly to our anycast IP addresses
                        for optimal routing.
                      </AlertDescription>
                    </Alert>

                    <div className="rounded-lg border bg-muted/50 p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm font-medium">Type: A</p>
                          <p className="text-xs text-muted-foreground">
                            Host: @ (or your subdomain)
                          </p>
                        </div>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() =>
                            copyToClipboard("192.0.2.1", "Primary IP address")
                          }
                        >
                          <ClipboardCopy className="h-4 w-4 mr-2" />
                          Copy IP
                        </Button>
                      </div>
                      <code className="block rounded bg-background p-3 text-sm font-mono">
                        @ IN A 192.0.2.1
                        <br />@ IN A 192.0.2.2
                      </code>
                      <p className="text-xs text-muted-foreground">
                        TTL: 300 (5 minutes) recommended
                      </p>
                    </div>
                  </TabsContent>

                  <TabsContent value="cname" className="space-y-4">
                    <Alert>
                      <Terminal className="h-4 w-4" />
                      <AlertTitle>CNAME Configuration</AlertTitle>
                      <AlertDescription>
                        Use our proxy hostname for automatic failover and load
                        balancing.
                      </AlertDescription>
                    </Alert>

                    <div className="rounded-lg border bg-muted/50 p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm font-medium">Type: CNAME</p>
                          <p className="text-xs text-muted-foreground">
                            Host: your subdomain
                          </p>
                        </div>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() =>
                            copyToClipboard(
                              `${selectedBackend ?? backends.backends[0]?.id}.proxy.pistonprotection.io`,
                              "CNAME target",
                            )
                          }
                        >
                          <ClipboardCopy className="h-4 w-4 mr-2" />
                          Copy Target
                        </Button>
                      </div>
                      <code className="block rounded bg-background p-3 text-sm font-mono">
                        play IN CNAME{" "}
                        {selectedBackend ?? backends.backends[0]?.id}
                        .proxy.pistonprotection.io
                      </code>
                      <p className="text-xs text-muted-foreground">
                        Note: CNAME cannot be used on root domain (@)
                      </p>
                    </div>
                  </TabsContent>

                  <TabsContent value="srv" className="space-y-4">
                    <Alert>
                      <Server className="h-4 w-4" />
                      <AlertTitle>SRV Record for Minecraft</AlertTitle>
                      <AlertDescription>
                        Allow players to connect using your domain without
                        specifying a port.
                      </AlertDescription>
                    </Alert>

                    <div className="rounded-lg border bg-muted/50 p-4 space-y-3">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm font-medium">Type: SRV</p>
                          <p className="text-xs text-muted-foreground">
                            Service: _minecraft._tcp
                          </p>
                        </div>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() =>
                            copyToClipboard(
                              `_minecraft._tcp.yourdomain.com. 0 5 25565 ${selectedBackend ?? backends.backends[0]?.id}.proxy.pistonprotection.io.`,
                              "SRV record",
                            )
                          }
                        >
                          <ClipboardCopy className="h-4 w-4 mr-2" />
                          Copy Record
                        </Button>
                      </div>
                      <code className="block rounded bg-background p-3 text-sm font-mono whitespace-pre-wrap">
                        _minecraft._tcp IN SRV 0 5 25565{" "}
                        {selectedBackend ?? backends.backends[0]?.id}
                        .proxy.pistonprotection.io.
                      </code>
                      <p className="text-xs text-muted-foreground">
                        Priority: 0, Weight: 5, Port: 25565
                      </p>
                    </div>

                    <Alert
                      variant="default"
                      className="bg-blue-500/5 border-blue-500/20"
                    >
                      <Badge className="bg-blue-500">Bedrock</Badge>
                      <AlertDescription className="mt-2">
                        For Minecraft Bedrock Edition, players connect directly
                        to the proxy hostname on port 19132. SRV records are not
                        supported for Bedrock.
                      </AlertDescription>
                    </Alert>
                  </TabsContent>
                </Tabs>
              </div>
            </>
          ) : (
            <Alert>
              <Server className="h-4 w-4" />
              <AlertTitle>No backends configured</AlertTitle>
              <AlertDescription>
                Create your first backend to get DNS configuration details.
                <Link to="/dashboard/backends">
                  <Button variant="link" className="h-auto p-0 ml-2">
                    Create Backend <ArrowRight className="h-3 w-3 ml-1" />
                  </Button>
                </Link>
              </AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* HAProxy Protocol Configuration */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Backend Server Configuration
          </CardTitle>
          <CardDescription>
            Configure your origin server to work with PistonProtection
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Accordion type="single" collapsible className="w-full">
            <AccordionItem value="haproxy">
              <AccordionTrigger>HAProxy Protocol Support</AccordionTrigger>
              <AccordionContent className="space-y-4">
                <p className="text-sm text-muted-foreground">
                  Enable HAProxy PROXY protocol to receive the original client
                  IP address on your backend server. This is required for
                  accurate logging and rate limiting.
                </p>

                <div className="space-y-3">
                  <h5 className="font-medium text-sm">
                    For Nginx (as TCP proxy):
                  </h5>
                  <div className="rounded-lg border bg-muted/50 p-4">
                    <code className="block text-sm font-mono whitespace-pre">
                      {`stream {
    server {
        listen 25565 proxy_protocol;
        proxy_pass backend:25565;

        # Log real client IP
        set_real_ip_from 192.0.2.0/24;
        real_ip_header proxy_protocol;
    }
}`}
                    </code>
                  </div>
                </div>

                <div className="space-y-3">
                  <h5 className="font-medium text-sm">For HAProxy:</h5>
                  <div className="rounded-lg border bg-muted/50 p-4">
                    <code className="block text-sm font-mono whitespace-pre">
                      {`frontend minecraft_front
    bind *:25565 accept-proxy
    default_backend minecraft_back

backend minecraft_back
    server mc1 127.0.0.1:25566`}
                    </code>
                  </div>
                </div>

                <div className="space-y-3">
                  <h5 className="font-medium text-sm">
                    For Velocity (Minecraft):
                  </h5>
                  <div className="rounded-lg border bg-muted/50 p-4">
                    <code className="block text-sm font-mono whitespace-pre">
                      {`# velocity.toml
[advanced]
haproxy-protocol = true`}
                    </code>
                  </div>
                </div>

                <div className="space-y-3">
                  <h5 className="font-medium text-sm">
                    For BungeeCord/Waterfall:
                  </h5>
                  <div className="rounded-lg border bg-muted/50 p-4">
                    <code className="block text-sm font-mono whitespace-pre">
                      {`# config.yml
proxy_protocol: true`}
                    </code>
                  </div>
                </div>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="firewall">
              <AccordionTrigger>Firewall Configuration</AccordionTrigger>
              <AccordionContent className="space-y-4">
                <Alert variant="destructive">
                  <Shield className="h-4 w-4" />
                  <AlertTitle>Important</AlertTitle>
                  <AlertDescription>
                    Block direct connections to your origin server to ensure all
                    traffic passes through PistonProtection.
                  </AlertDescription>
                </Alert>

                <div className="space-y-3">
                  <h5 className="font-medium text-sm">
                    iptables (allow only PistonProtection IPs):
                  </h5>
                  <div className="rounded-lg border bg-muted/50 p-4">
                    <code className="block text-sm font-mono whitespace-pre">
                      {`# Allow PistonProtection proxy servers
iptables -A INPUT -p tcp --dport 25565 -s 192.0.2.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 25565 -s 198.51.100.0/24 -j ACCEPT

# Drop all other connections to the protected port
iptables -A INPUT -p tcp --dport 25565 -j DROP`}
                    </code>
                  </div>
                </div>

                <div className="space-y-3">
                  <h5 className="font-medium text-sm">UFW (Ubuntu):</h5>
                  <div className="rounded-lg border bg-muted/50 p-4">
                    <code className="block text-sm font-mono whitespace-pre">
                      {`# Allow PistonProtection IPs
sudo ufw allow from 192.0.2.0/24 to any port 25565
sudo ufw allow from 198.51.100.0/24 to any port 25565

# Deny others
sudo ufw deny 25565`}
                    </code>
                  </div>
                </div>

                <p className="text-xs text-muted-foreground">
                  View the full list of PistonProtection IP ranges in your{" "}
                  <Link
                    to="/dashboard/settings"
                    className="text-primary underline"
                  >
                    account settings
                  </Link>
                  .
                </p>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="health">
              <AccordionTrigger>Health Check Configuration</AccordionTrigger>
              <AccordionContent className="space-y-4">
                <p className="text-sm text-muted-foreground">
                  PistonProtection monitors your backend health and
                  automatically routes traffic away from unhealthy servers.
                </p>

                <div className="space-y-3">
                  <h5 className="font-medium text-sm">Health Check Details:</h5>
                  <div className="grid gap-3 md:grid-cols-2">
                    <div className="rounded-lg border p-3">
                      <p className="text-sm font-medium">TCP Health Checks</p>
                      <p className="text-xs text-muted-foreground">
                        Verifies TCP connection to your backend port
                      </p>
                    </div>
                    <div className="rounded-lg border p-3">
                      <p className="text-sm font-medium">
                        Protocol Health Checks
                      </p>
                      <p className="text-xs text-muted-foreground">
                        Minecraft: Sends status ping, HTTP: GET /health
                      </p>
                    </div>
                    <div className="rounded-lg border p-3">
                      <p className="text-sm font-medium">Check Interval</p>
                      <p className="text-xs text-muted-foreground">
                        Every 30 seconds (configurable)
                      </p>
                    </div>
                    <div className="rounded-lg border p-3">
                      <p className="text-sm font-medium">Failure Threshold</p>
                      <p className="text-xs text-muted-foreground">
                        3 consecutive failures marks unhealthy
                      </p>
                    </div>
                  </div>
                </div>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="fallback">
              <AccordionTrigger>Fallback Server (Minecraft)</AccordionTrigger>
              <AccordionContent className="space-y-4">
                <p className="text-sm text-muted-foreground">
                  Configure a fallback message shown to players when your server
                  is offline or under maintenance.
                </p>

                <div className="rounded-lg border bg-muted/50 p-4">
                  <p className="text-sm font-medium mb-2">Default Fallback:</p>
                  <div className="rounded bg-background p-3 border">
                    <p className="text-red-500 font-mono text-sm">
                      Server is currently offline. Please try again later.
                    </p>
                  </div>
                </div>

                <p className="text-xs text-muted-foreground">
                  Customize the fallback message and MOTD in your{" "}
                  <Link
                    to="/dashboard/backends"
                    className="text-primary underline"
                  >
                    backend settings
                  </Link>
                  .
                </p>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </CardContent>
      </Card>

      {/* Quick Links */}
      <Card>
        <CardHeader>
          <CardTitle>Documentation & Support</CardTitle>
          <CardDescription>
            Additional resources to help you get started
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 md:grid-cols-3">
            <Link to="/docs" className="block">
              <div className="rounded-lg border p-4 hover:bg-muted/50 transition-colors">
                <div className="flex items-center gap-2">
                  <ExternalLink className="h-4 w-4" />
                  <span className="font-medium">Documentation</span>
                </div>
                <p className="text-sm text-muted-foreground mt-1">
                  Comprehensive guides and API reference
                </p>
              </div>
            </Link>

            <a
              href="https://github.com/pistonprotection"
              target="_blank"
              rel="noopener noreferrer"
              className="block"
            >
              <div className="rounded-lg border p-4 hover:bg-muted/50 transition-colors">
                <div className="flex items-center gap-2">
                  <ExternalLink className="h-4 w-4" />
                  <span className="font-medium">GitHub</span>
                </div>
                <p className="text-sm text-muted-foreground mt-1">
                  Open source code and examples
                </p>
              </div>
            </a>

            <a href="mailto:support@pistonprotection.io" className="block">
              <div className="rounded-lg border p-4 hover:bg-muted/50 transition-colors">
                <div className="flex items-center gap-2">
                  <ExternalLink className="h-4 w-4" />
                  <span className="font-medium">Support</span>
                </div>
                <p className="text-sm text-muted-foreground mt-1">
                  Contact our team for help
                </p>
              </div>
            </a>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
