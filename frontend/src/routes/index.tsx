import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Activity,
  ArrowRight,
  BarChart3,
  Check,
  Cloud,
  Code2,
  Cpu,
  ExternalLink,
  Gamepad2,
  Github,
  Globe,
  HardDrive,
  Lock,
  Menu,
  Network,
  Server,
  Shield,
  ShieldCheck,
  Timer,
  Users,
  Zap,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";

export const Route = createFileRoute("/")({
  component: LandingPage,
  head: () => ({
    meta: [
      { title: "PistonProtection - Enterprise DDoS Protection with eBPF/XDP" },
      {
        name: "description",
        content:
          "Self-hostable, enterprise-grade DDoS protection platform powered by eBPF/XDP. Protect TCP, UDP, HTTP, QUIC, and Minecraft servers with sub-millisecond latency filtering.",
      },
      {
        name: "keywords",
        content:
          "DDoS protection, eBPF, XDP, Minecraft protection, game server protection, TCP proxy, UDP proxy, anti-DDoS, self-hosted",
      },
      {
        property: "og:title",
        content: "PistonProtection - Enterprise DDoS Protection",
      },
      {
        property: "og:description",
        content:
          "Open-source, self-hostable DDoS protection with eBPF/XDP kernel-level filtering.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
      { name: "twitter:title", content: "PistonProtection - DDoS Protection" },
    ],
  }),
});

function LandingPage() {
  const features = [
    {
      icon: Shield,
      title: "eBPF/XDP Filtering",
      description:
        "Kernel-level packet filtering drops malicious traffic before it reaches userspace, handling millions of packets per second.",
    },
    {
      icon: Zap,
      title: "Sub-millisecond Latency",
      description:
        "XDP processes packets at wire speed with minimal overhead. Your legitimate users experience virtually no added latency.",
    },
    {
      icon: Globe,
      title: "GeoDNS Load Balancing",
      description:
        "Route traffic to the nearest edge node with intelligent geographic DNS resolution and health-aware failover.",
    },
    {
      icon: Server,
      title: "Multi-Protocol Support",
      description:
        "Native protocol understanding for TCP, UDP, HTTP/1-3, QUIC, Minecraft Java/Bedrock, and custom protocols.",
    },
    {
      icon: Lock,
      title: "HAProxy Protocol",
      description:
        "Preserve real client IPs with HAProxy protocol v1/v2 support for seamless backend integration.",
    },
    {
      icon: BarChart3,
      title: "Real-time Analytics",
      description:
        "Live traffic visualization, attack detection metrics, and historical analysis with Grafana dashboards.",
    },
    {
      icon: Cpu,
      title: "IP Scoring System",
      description:
        "Automatic reputation scoring tracks suspicious IPs, enabling intelligent rate limiting and blocking decisions.",
    },
    {
      icon: Cloud,
      title: "Kubernetes Native",
      description:
        "Deploy on Kubernetes with Cilium CNI. Custom CRDs, Helm charts, and operator for declarative management.",
    },
  ];

  const protocols = [
    {
      name: "HTTP/1.1",
      icon: Globe,
      attacks: ["Slowloris", "HTTP Flood", "Header Injection"],
    },
    {
      name: "HTTP/2",
      icon: Network,
      attacks: ["Stream Flood", "HPACK Bomb", "Reset Attack"],
    },
    {
      name: "HTTP/3 (QUIC)",
      icon: Zap,
      attacks: ["Initial Flood", "Retry Amplification", "Connection Flood"],
    },
    {
      name: "Minecraft Java",
      icon: Gamepad2,
      attacks: ["Handshake Flood", "Bot Joins", "Packet Spam"],
    },
    {
      name: "Minecraft Bedrock",
      icon: Gamepad2,
      attacks: ["RakNet Amplification", "Ping Flood", "MOTD Abuse"],
    },
    {
      name: "Generic TCP",
      icon: Server,
      attacks: ["SYN Flood", "ACK Flood", "RST Attack", "Slow Read"],
    },
    {
      name: "Generic UDP",
      icon: HardDrive,
      attacks: ["Amplification", "Fragmentation", "Port Scan"],
    },
    {
      name: "QUIC",
      icon: Lock,
      attacks: ["Version Negotiation", "Token Validation", "Retry Storm"],
    },
  ];

  const stats = [
    { value: "10M+", label: "Packets/sec per node" },
    { value: "<1ms", label: "Added latency" },
    { value: "99.99%", label: "Uptime SLA" },
    { value: "24/7", label: "Attack monitoring" },
  ];

  const plans = [
    {
      name: "Starter",
      price: 49,
      description: "Perfect for small servers and personal projects",
      features: [
        "1 TB Clean Bandwidth",
        "5 Protected Backends",
        "25 Custom Filter Rules",
        "Basic Attack Mitigation",
        "Email Support",
        "7-day Log Retention",
      ],
      cta: "Get Started",
    },
    {
      name: "Professional",
      price: 199,
      description: "For growing communities and businesses",
      features: [
        "5 TB Clean Bandwidth",
        "15 Protected Backends",
        "100 Custom Filter Rules",
        "Advanced Attack Mitigation",
        "Priority Support",
        "30-day Log Retention",
        "Custom Filter Rules",
        "GeoDNS Load Balancing",
        "HAProxy Protocol Support",
      ],
      popular: true,
      cta: "Start Free Trial",
    },
    {
      name: "Enterprise",
      price: 499,
      description: "For large networks requiring maximum protection",
      features: [
        "Unlimited Bandwidth",
        "Unlimited Backends",
        "Unlimited Filter Rules",
        "Maximum Attack Mitigation",
        "24/7 Dedicated Support",
        "90-day Log Retention",
        "Custom Integration",
        "Dedicated Edge Nodes",
        "99.99% SLA Guarantee",
        "On-premise Deployment",
      ],
      cta: "Contact Sales",
    },
  ];

  const comparisons = [
    { feature: "eBPF/XDP Kernel Filtering", piston: true, others: false },
    { feature: "Self-Hostable / Open Source", piston: true, others: false },
    { feature: "Minecraft Protocol Support", piston: true, others: "Partial" },
    { feature: "HTTP/3 & QUIC Protection", piston: true, others: "Limited" },
    { feature: "HAProxy Protocol v2", piston: true, others: true },
    { feature: "Real-time Analytics", piston: true, others: true },
    { feature: "GeoDNS Load Balancing", piston: true, others: true },
    { feature: "Custom Filter Rules", piston: true, others: "Limited" },
    { feature: "API Access", piston: true, others: true },
    { feature: "Kubernetes Native", piston: true, others: false },
  ];

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto flex h-16 items-center justify-between px-4">
          <div className="flex items-center gap-2">
            <Shield className="h-7 w-7 text-primary" />
            <span className="font-bold text-xl">PistonProtection</span>
          </div>
          <nav className="hidden md:flex items-center gap-8">
            <a
              href="#features"
              className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
            >
              Features
            </a>
            <a
              href="#protocols"
              className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
            >
              Protocols
            </a>
            <a
              href="#pricing"
              className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
            >
              Pricing
            </a>
            <Link
              to="/docs"
              className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
            >
              Documentation
            </Link>
            <a
              href="https://github.com/PistonProtection/pistonprotection"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm font-medium text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1"
            >
              <Github className="h-4 w-4" />
              GitHub
            </a>
          </nav>
          <div className="flex items-center gap-3">
            <Link to="/auth/login" className="hidden sm:block">
              <Button variant="ghost">Sign In</Button>
            </Link>
            <Link to="/auth/register">
              <Button>Get Started</Button>
            </Link>
            <Button variant="ghost" size="icon" className="md:hidden">
              <Menu className="h-5 w-5" />
            </Button>
          </div>
        </div>
      </header>

      <main>
        {/* Hero Section */}
        <section className="relative overflow-hidden py-24 md:py-32 lg:py-40">
          <div className="absolute inset-0 bg-gradient-to-b from-primary/5 to-transparent" />
          <div className="container mx-auto px-4 relative">
            <div className="max-w-4xl mx-auto text-center">
              <Badge className="mb-6" variant="secondary">
                <Code2 className="h-3 w-3 mr-1" />
                Open Source & Self-Hostable
              </Badge>
              <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold tracking-tight mb-6 bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text">
                Enterprise DDoS Protection
                <br />
                <span className="text-primary">Powered by eBPF/XDP</span>
              </h1>
              <p className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto mb-8 leading-relaxed">
                Stop volumetric attacks at the network edge with kernel-level
                packet filtering. Protect TCP, UDP, HTTP, QUIC, and game servers
                with sub-millisecond latency.
              </p>
              <div className="flex flex-col sm:flex-row gap-4 justify-center mb-12">
                <Link to="/auth/register">
                  <Button size="lg" className="w-full sm:w-auto">
                    Start Free Trial
                    <ArrowRight className="ml-2 h-4 w-4" />
                  </Button>
                </Link>
                <a
                  href="https://github.com/PistonProtection/pistonprotection"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <Button
                    size="lg"
                    variant="outline"
                    className="w-full sm:w-auto"
                  >
                    <Github className="mr-2 h-4 w-4" />
                    View on GitHub
                  </Button>
                </a>
              </div>
              <div className="flex flex-wrap items-center justify-center gap-x-8 gap-y-4 text-sm text-muted-foreground">
                <div className="flex items-center gap-2">
                  <Check className="h-4 w-4 text-green-500" />
                  No credit card required
                </div>
                <div className="flex items-center gap-2">
                  <Check className="h-4 w-4 text-green-500" />
                  14-day free trial
                </div>
                <div className="flex items-center gap-2">
                  <Check className="h-4 w-4 text-green-500" />
                  Self-host option available
                </div>
                <div className="flex items-center gap-2">
                  <Check className="h-4 w-4 text-green-500" />
                  Apache 2.0 License
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Stats Section */}
        <section className="border-y bg-muted/30 py-12">
          <div className="container mx-auto px-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-8 text-center">
              {stats.map((stat, i) => (
                <div key={i}>
                  <div className="text-3xl md:text-4xl font-bold text-primary mb-1">
                    {stat.value}
                  </div>
                  <div className="text-sm text-muted-foreground">
                    {stat.label}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section id="features" className="py-20 md:py-28">
          <div className="container mx-auto px-4">
            <div className="text-center mb-16">
              <Badge className="mb-4" variant="outline">
                <Cpu className="h-3 w-3 mr-1" />
                Features
              </Badge>
              <h2 className="text-3xl md:text-4xl font-bold mb-4">
                Built for Modern Infrastructure
              </h2>
              <p className="text-muted-foreground max-w-2xl mx-auto text-lg">
                eBPF/XDP technology operates at the Linux kernel level,
                processing packets before they reach the network stack for
                maximum performance.
              </p>
            </div>
            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
              {features.map((f, i) => (
                <Card
                  key={i}
                  className="group hover:border-primary/50 transition-colors"
                >
                  <CardHeader>
                    <div className="mb-3 p-2 rounded-lg bg-primary/10 w-fit group-hover:bg-primary/20 transition-colors">
                      <f.icon className="h-6 w-6 text-primary" />
                    </div>
                    <CardTitle className="text-lg">{f.title}</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <CardDescription className="text-sm leading-relaxed">
                      {f.description}
                    </CardDescription>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </section>

        {/* Protocols Section */}
        <section id="protocols" className="py-20 md:py-28 bg-muted/30">
          <div className="container mx-auto px-4">
            <div className="text-center mb-16">
              <Badge className="mb-4" variant="outline">
                <Network className="h-3 w-3 mr-1" />
                Protocols
              </Badge>
              <h2 className="text-3xl md:text-4xl font-bold mb-4">
                Protocol-Aware Protection
              </h2>
              <p className="text-muted-foreground max-w-2xl mx-auto text-lg">
                Deep packet inspection with protocol-specific filtering rules.
                Each protocol has tailored detection for known attack vectors.
              </p>
            </div>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              {protocols.map((p, i) => (
                <Card key={i} className="group">
                  <CardHeader className="pb-3">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-primary/10">
                        <p.icon className="h-5 w-5 text-primary" />
                      </div>
                      <CardTitle className="text-base">{p.name}</CardTitle>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="flex flex-wrap gap-1.5">
                      {p.attacks.map((attack, j) => (
                        <Badge
                          key={j}
                          variant="secondary"
                          className="text-xs font-normal"
                        >
                          {attack}
                        </Badge>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </section>

        {/* How It Works Section */}
        <section className="py-20 md:py-28">
          <div className="container mx-auto px-4">
            <div className="text-center mb-16">
              <Badge className="mb-4" variant="outline">
                <Activity className="h-3 w-3 mr-1" />
                How It Works
              </Badge>
              <h2 className="text-3xl md:text-4xl font-bold mb-4">
                Protection at Wire Speed
              </h2>
              <p className="text-muted-foreground max-w-2xl mx-auto text-lg">
                Traffic flows through our XDP-powered edge nodes before reaching
                your servers.
              </p>
            </div>
            <div className="max-w-4xl mx-auto">
              <div className="grid md:grid-cols-3 gap-8">
                <div className="text-center">
                  <div className="mb-4 mx-auto w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center">
                    <Globe className="h-8 w-8 text-primary" />
                  </div>
                  <h3 className="font-semibold mb-2">1. Traffic Arrives</h3>
                  <p className="text-sm text-muted-foreground">
                    Incoming traffic reaches our edge network via Anycast or
                    GeoDNS routing.
                  </p>
                </div>
                <div className="text-center">
                  <div className="mb-4 mx-auto w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center">
                    <ShieldCheck className="h-8 w-8 text-primary" />
                  </div>
                  <h3 className="font-semibold mb-2">2. XDP Filters</h3>
                  <p className="text-sm text-muted-foreground">
                    eBPF programs inspect and filter packets at the kernel level
                    before userspace.
                  </p>
                </div>
                <div className="text-center">
                  <div className="mb-4 mx-auto w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center">
                    <Server className="h-8 w-8 text-primary" />
                  </div>
                  <h3 className="font-semibold mb-2">3. Clean Traffic</h3>
                  <p className="text-sm text-muted-foreground">
                    Only legitimate traffic is proxied to your backend servers
                    with real client IPs.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Comparison Section */}
        <section className="py-20 md:py-28 bg-muted/30">
          <div className="container mx-auto px-4">
            <div className="text-center mb-16">
              <Badge className="mb-4" variant="outline">
                <Users className="h-3 w-3 mr-1" />
                Comparison
              </Badge>
              <h2 className="text-3xl md:text-4xl font-bold mb-4">
                Why Choose PistonProtection?
              </h2>
              <p className="text-muted-foreground max-w-2xl mx-auto text-lg">
                See how we compare to traditional DDoS protection services.
              </p>
            </div>
            <div className="max-w-3xl mx-auto">
              <Card>
                <CardContent className="p-0">
                  <div className="grid grid-cols-3 gap-4 p-4 border-b bg-muted/50 font-semibold">
                    <div>Feature</div>
                    <div className="text-center">PistonProtection</div>
                    <div className="text-center text-muted-foreground">
                      Others
                    </div>
                  </div>
                  {comparisons.map((c, i) => (
                    <div
                      key={i}
                      className="grid grid-cols-3 gap-4 p-4 border-b last:border-0 items-center"
                    >
                      <div className="text-sm">{c.feature}</div>
                      <div className="text-center">
                        {c.piston === true ? (
                          <Check className="h-5 w-5 text-green-500 mx-auto" />
                        ) : (
                          <span className="text-sm text-muted-foreground">
                            {c.piston}
                          </span>
                        )}
                      </div>
                      <div className="text-center">
                        {c.others === true ? (
                          <Check className="h-5 w-5 text-green-500 mx-auto" />
                        ) : c.others === false ? (
                          <span className="text-muted-foreground">-</span>
                        ) : (
                          <span className="text-sm text-muted-foreground">
                            {c.others}
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>
          </div>
        </section>

        {/* Pricing Section */}
        <section id="pricing" className="py-20 md:py-28">
          <div className="container mx-auto px-4">
            <div className="text-center mb-16">
              <Badge className="mb-4" variant="outline">
                <Timer className="h-3 w-3 mr-1" />
                Pricing
              </Badge>
              <h2 className="text-3xl md:text-4xl font-bold mb-4">
                Simple, Transparent Pricing
              </h2>
              <p className="text-muted-foreground max-w-2xl mx-auto text-lg">
                Choose the plan that fits your needs. All plans include our core
                protection features.
              </p>
            </div>
            <div className="grid gap-8 md:grid-cols-3 max-w-6xl mx-auto">
              {plans.map((p, i) => (
                <Card
                  key={i}
                  className={`relative ${p.popular ? "border-primary shadow-lg scale-105" : ""}`}
                >
                  {p.popular && (
                    <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                      <Badge>Most Popular</Badge>
                    </div>
                  )}
                  <CardHeader className="text-center pb-4">
                    <CardTitle className="text-xl">{p.name}</CardTitle>
                    <div className="mt-4">
                      <span className="text-4xl font-bold">${p.price}</span>
                      <span className="text-muted-foreground">/month</span>
                    </div>
                    <CardDescription className="mt-2">
                      {p.description}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <ul className="space-y-3">
                      {p.features.map((f, j) => (
                        <li key={j} className="flex items-start gap-3 text-sm">
                          <Check className="h-4 w-4 text-green-500 mt-0.5 shrink-0" />
                          <span>{f}</span>
                        </li>
                      ))}
                    </ul>
                    <Link to="/auth/register" className="block">
                      <Button
                        className="w-full"
                        variant={p.popular ? "default" : "outline"}
                        size="lg"
                      >
                        {p.cta}
                      </Button>
                    </Link>
                  </CardContent>
                </Card>
              ))}
            </div>
            <div className="text-center mt-12">
              <p className="text-muted-foreground mb-4">
                Need a custom solution? Want to self-host?
              </p>
              <a
                href="https://github.com/PistonProtection/pistonprotection"
                target="_blank"
                rel="noopener noreferrer"
              >
                <Button variant="link" className="text-primary">
                  Deploy on your own infrastructure
                  <ExternalLink className="ml-1 h-4 w-4" />
                </Button>
              </a>
            </div>
          </div>
        </section>

        {/* CTA Section */}
        <section className="py-20 md:py-28 bg-primary text-primary-foreground">
          <div className="container mx-auto px-4 text-center">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Ready to Protect Your Infrastructure?
            </h2>
            <p className="text-primary-foreground/80 max-w-2xl mx-auto mb-8 text-lg">
              Join thousands of servers protected by PistonProtection. Start
              your free trial today or deploy on your own infrastructure.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link to="/auth/register">
                <Button size="lg" variant="secondary">
                  Start Free Trial
                  <ArrowRight className="ml-2 h-4 w-4" />
                </Button>
              </Link>
              <Link to="/docs">
                <Button
                  size="lg"
                  variant="outline"
                  className="bg-transparent border-primary-foreground/20 hover:bg-primary-foreground/10"
                >
                  Read Documentation
                </Button>
              </Link>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t py-16 bg-muted/30">
        <div className="container mx-auto px-4">
          <div className="grid gap-8 md:grid-cols-4 mb-12">
            <div>
              <div className="flex items-center gap-2 mb-4">
                <Shield className="h-6 w-6 text-primary" />
                <span className="font-bold text-lg">PistonProtection</span>
              </div>
              <p className="text-sm text-muted-foreground mb-4">
                Open-source, enterprise-grade DDoS protection powered by
                eBPF/XDP.
              </p>
              <div className="flex gap-4">
                <a
                  href="https://github.com/PistonProtection"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-muted-foreground hover:text-foreground transition-colors"
                >
                  <Github className="h-5 w-5" />
                </a>
              </div>
            </div>
            <div>
              <h4 className="font-semibold mb-4">Product</h4>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li>
                  <a
                    href="#features"
                    className="hover:text-foreground transition-colors"
                  >
                    Features
                  </a>
                </li>
                <li>
                  <a
                    href="#pricing"
                    className="hover:text-foreground transition-colors"
                  >
                    Pricing
                  </a>
                </li>
                <li>
                  <Link
                    to="/docs"
                    className="hover:text-foreground transition-colors"
                  >
                    Documentation
                  </Link>
                </li>
                <li>
                  <a
                    href="https://github.com/PistonProtection/pistonprotection/releases"
                    className="hover:text-foreground transition-colors"
                  >
                    Changelog
                  </a>
                </li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-4">Resources</h4>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li>
                  <Link
                    to="/docs"
                    className="hover:text-foreground transition-colors"
                  >
                    Getting Started
                  </Link>
                </li>
                <li>
                  <Link
                    to="/docs"
                    className="hover:text-foreground transition-colors"
                  >
                    API Reference
                  </Link>
                </li>
                <li>
                  <a
                    href="https://github.com/PistonProtection/pistonprotection"
                    className="hover:text-foreground transition-colors"
                  >
                    GitHub
                  </a>
                </li>
                <li>
                  <a
                    href="https://github.com/PistonProtection/pistonprotection/issues"
                    className="hover:text-foreground transition-colors"
                  >
                    Support
                  </a>
                </li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-4">Legal</h4>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li>
                  <Link
                    to="/privacy"
                    className="hover:text-foreground transition-colors"
                  >
                    Privacy Policy
                  </Link>
                </li>
                <li>
                  <Link
                    to="/terms"
                    className="hover:text-foreground transition-colors"
                  >
                    Terms of Service
                  </Link>
                </li>
                <li>
                  <a
                    href="https://github.com/PistonProtection/pistonprotection/blob/main/LICENSE"
                    className="hover:text-foreground transition-colors"
                  >
                    License (Apache 2.0)
                  </a>
                </li>
              </ul>
            </div>
          </div>
          <Separator className="mb-8" />
          <div className="flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-muted-foreground">
            <p>
              © {new Date().getFullYear()} PistonProtection. All rights
              reserved.
            </p>
            <p>Built with eBPF, Rust, and React</p>
          </div>
        </div>
      </footer>
    </div>
  );
}
