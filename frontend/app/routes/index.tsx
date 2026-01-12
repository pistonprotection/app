import { createFileRoute, Link } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Shield,
  Zap,
  Globe,
  Server,
  BarChart3,
  Lock,
  ArrowRight,
  Check,
} from "lucide-react";

export const Route = createFileRoute("/")({
  component: HomePage,
});

function HomePage() {
  return (
    <div className="flex min-h-screen flex-col">
      {/* Navigation */}
      <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-primary" />
            <span className="text-xl font-bold">PistonProtection</span>
          </div>
          <nav className="hidden md:flex items-center gap-6">
            <Link to="/" className="text-sm font-medium text-muted-foreground hover:text-foreground">
              Features
            </Link>
            <Link to="/" className="text-sm font-medium text-muted-foreground hover:text-foreground">
              Pricing
            </Link>
            <Link to="/" className="text-sm font-medium text-muted-foreground hover:text-foreground">
              Documentation
            </Link>
          </nav>
          <div className="flex items-center gap-4">
            <Link to="/auth/login">
              <Button variant="ghost">Sign In</Button>
            </Link>
            <Link to="/auth/register">
              <Button>Get Started</Button>
            </Link>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="container flex flex-col items-center justify-center gap-6 py-24 text-center md:py-32">
        <Badge variant="secondary" className="px-4 py-1">
          <Zap className="mr-1 h-3 w-3" />
          Now with eBPF/XDP Acceleration
        </Badge>
        <h1 className="text-4xl font-bold tracking-tighter sm:text-5xl md:text-6xl lg:text-7xl">
          Enterprise DDoS Protection
          <br />
          <span className="text-muted-foreground">at Line Rate</span>
        </h1>
        <p className="max-w-[700px] text-lg text-muted-foreground md:text-xl">
          Protect your game servers, web applications, and infrastructure with
          advanced eBPF/XDP filtering. Handle millions of packets per second
          with near-zero latency.
        </p>
        <div className="flex flex-col gap-4 sm:flex-row">
          <Link to="/auth/register">
            <Button size="lg" className="gap-2">
              Start Free Trial <ArrowRight className="h-4 w-4" />
            </Button>
          </Link>
          <Link to="/">
            <Button variant="outline" size="lg">
              View Documentation
            </Button>
          </Link>
        </div>

        {/* Stats */}
        <div className="mt-12 grid grid-cols-2 gap-8 md:grid-cols-4">
          <div className="flex flex-col items-center gap-2">
            <span className="text-4xl font-bold">10M+</span>
            <span className="text-sm text-muted-foreground">PPS Capacity</span>
          </div>
          <div className="flex flex-col items-center gap-2">
            <span className="text-4xl font-bold">&lt;1ms</span>
            <span className="text-sm text-muted-foreground">Added Latency</span>
          </div>
          <div className="flex flex-col items-center gap-2">
            <span className="text-4xl font-bold">99.99%</span>
            <span className="text-sm text-muted-foreground">Uptime SLA</span>
          </div>
          <div className="flex flex-col items-center gap-2">
            <span className="text-4xl font-bold">50+</span>
            <span className="text-sm text-muted-foreground">Global PoPs</span>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="container py-24">
        <div className="text-center mb-16">
          <h2 className="text-3xl font-bold tracking-tighter sm:text-4xl">
            Built for Modern Infrastructure
          </h2>
          <p className="mt-4 text-lg text-muted-foreground">
            Advanced protection features designed for high-performance workloads
          </p>
        </div>

        <div className="grid gap-8 md:grid-cols-2 lg:grid-cols-3">
          <Card>
            <CardHeader>
              <Zap className="h-10 w-10 text-primary mb-2" />
              <CardTitle>eBPF/XDP Filtering</CardTitle>
              <CardDescription>
                Process packets at kernel level before they reach userspace for
                maximum throughput and minimal latency.
              </CardDescription>
            </CardHeader>
          </Card>

          <Card>
            <CardHeader>
              <Server className="h-10 w-10 text-primary mb-2" />
              <CardTitle>Game Server Protection</CardTitle>
              <CardDescription>
                Native support for Minecraft Java/Bedrock, QUIC, and custom
                protocols with deep packet inspection.
              </CardDescription>
            </CardHeader>
          </Card>

          <Card>
            <CardHeader>
              <Globe className="h-10 w-10 text-primary mb-2" />
              <CardTitle>Global Anycast Network</CardTitle>
              <CardDescription>
                Distribute traffic across 50+ points of presence worldwide for
                optimal routing and redundancy.
              </CardDescription>
            </CardHeader>
          </Card>

          <Card>
            <CardHeader>
              <BarChart3 className="h-10 w-10 text-primary mb-2" />
              <CardTitle>Real-time Analytics</CardTitle>
              <CardDescription>
                Monitor traffic patterns, attack vectors, and mitigation
                effectiveness with sub-second metrics.
              </CardDescription>
            </CardHeader>
          </Card>

          <Card>
            <CardHeader>
              <Lock className="h-10 w-10 text-primary mb-2" />
              <CardTitle>Smart Rate Limiting</CardTitle>
              <CardDescription>
                Token bucket rate limiting with per-IP, per-subnet, and global
                limits to prevent abuse.
              </CardDescription>
            </CardHeader>
          </Card>

          <Card>
            <CardHeader>
              <Shield className="h-10 w-10 text-primary mb-2" />
              <CardTitle>Protocol Validation</CardTitle>
              <CardDescription>
                Deep protocol inspection validates TCP flags, handshakes, and
                application-layer protocols.
              </CardDescription>
            </CardHeader>
          </Card>
        </div>
      </section>

      {/* Pricing Section */}
      <section className="container py-24 bg-muted/50">
        <div className="text-center mb-16">
          <h2 className="text-3xl font-bold tracking-tighter sm:text-4xl">
            Simple, Transparent Pricing
          </h2>
          <p className="mt-4 text-lg text-muted-foreground">
            Choose the plan that fits your needs
          </p>
        </div>

        <div className="grid gap-8 md:grid-cols-3 max-w-5xl mx-auto">
          <Card>
            <CardHeader>
              <CardTitle>Starter</CardTitle>
              <CardDescription>For small projects</CardDescription>
              <div className="mt-4">
                <span className="text-4xl font-bold">$29</span>
                <span className="text-muted-foreground">/month</span>
              </div>
            </CardHeader>
            <CardContent>
              <ul className="space-y-3">
                {[
                  "1 Protected Backend",
                  "10 Gbps DDoS Protection",
                  "Basic Analytics",
                  "Email Support",
                ].map((feature) => (
                  <li key={feature} className="flex items-center gap-2">
                    <Check className="h-4 w-4 text-success" />
                    <span className="text-sm">{feature}</span>
                  </li>
                ))}
              </ul>
              <Button className="w-full mt-6" variant="outline">
                Get Started
              </Button>
            </CardContent>
          </Card>

          <Card className="border-primary">
            <CardHeader>
              <Badge className="w-fit mb-2">Most Popular</Badge>
              <CardTitle>Pro</CardTitle>
              <CardDescription>For growing businesses</CardDescription>
              <div className="mt-4">
                <span className="text-4xl font-bold">$99</span>
                <span className="text-muted-foreground">/month</span>
              </div>
            </CardHeader>
            <CardContent>
              <ul className="space-y-3">
                {[
                  "5 Protected Backends",
                  "100 Gbps DDoS Protection",
                  "Advanced Analytics",
                  "Priority Support",
                  "Custom Filter Rules",
                ].map((feature) => (
                  <li key={feature} className="flex items-center gap-2">
                    <Check className="h-4 w-4 text-success" />
                    <span className="text-sm">{feature}</span>
                  </li>
                ))}
              </ul>
              <Button className="w-full mt-6">Get Started</Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Enterprise</CardTitle>
              <CardDescription>For large organizations</CardDescription>
              <div className="mt-4">
                <span className="text-4xl font-bold">Custom</span>
              </div>
            </CardHeader>
            <CardContent>
              <ul className="space-y-3">
                {[
                  "Unlimited Backends",
                  "1+ Tbps DDoS Protection",
                  "Real-time Analytics",
                  "24/7 Dedicated Support",
                  "Custom Integrations",
                  "SLA Guarantee",
                ].map((feature) => (
                  <li key={feature} className="flex items-center gap-2">
                    <Check className="h-4 w-4 text-success" />
                    <span className="text-sm">{feature}</span>
                  </li>
                ))}
              </ul>
              <Button className="w-full mt-6" variant="outline">
                Contact Sales
              </Button>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t py-12 mt-auto">
        <div className="container">
          <div className="flex flex-col md:flex-row justify-between items-center gap-4">
            <div className="flex items-center gap-2">
              <Shield className="h-6 w-6 text-primary" />
              <span className="font-semibold">PistonProtection</span>
            </div>
            <p className="text-sm text-muted-foreground">
              © 2024 PistonProtection. Open source under MIT License.
            </p>
            <div className="flex gap-4">
              <Link to="/" className="text-sm text-muted-foreground hover:text-foreground">
                Privacy
              </Link>
              <Link to="/" className="text-sm text-muted-foreground hover:text-foreground">
                Terms
              </Link>
              <Link to="/" className="text-sm text-muted-foreground hover:text-foreground">
                GitHub
              </Link>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
