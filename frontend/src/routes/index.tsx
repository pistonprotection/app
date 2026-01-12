import { createFileRoute, Link } from "@tanstack/react-router"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Shield, Zap, Globe, Server, ArrowRight, Check } from "lucide-react"

export const Route = createFileRoute("/")({ component: LandingPage })

function LandingPage() {
  const features = [
    { icon: Shield, title: "Advanced DDoS Protection", description: "eBPF/XDP-powered packet filtering stops attacks at the network edge." },
    { icon: Zap, title: "Sub-millisecond Latency", description: "Kernel-level protection adds virtually no latency to legitimate traffic." },
    { icon: Globe, title: "Global Anycast Network", description: "Traffic filtered across our worldwide network of scrubbing centers." },
    { icon: Server, title: "Multi-Protocol Support", description: "Protect TCP, UDP, HTTP, QUIC, and Minecraft traffic." },
  ]
  const plans = [
    { name: "Starter", price: 49, features: ["1 TB Bandwidth", "5 Backends", "25 Filters", "Email Support"], cta: "Get Started" },
    { name: "Professional", price: 199, features: ["5 TB Bandwidth", "15 Backends", "100 Filters", "Priority Support", "Custom Filters"], popular: true, cta: "Start Free Trial" },
    { name: "Enterprise", price: 499, features: ["Unlimited Bandwidth", "Unlimited Backends", "Unlimited Filters", "24/7 Support", "Dedicated IP", "99.99% SLA"], cta: "Contact Sales" },
  ]
  return (
    <div className="min-h-screen bg-background">
      <header className="border-b">
        <div className="container mx-auto flex h-16 items-center justify-between px-4">
          <div className="flex items-center gap-2"><Shield className="h-6 w-6 text-primary" /><span className="font-bold text-xl">PistonProtection</span></div>
          <nav className="hidden md:flex items-center gap-6"><a href="#features" className="text-sm text-muted-foreground hover:text-foreground">Features</a><a href="#pricing" className="text-sm text-muted-foreground hover:text-foreground">Pricing</a><a href="/docs" className="text-sm text-muted-foreground hover:text-foreground">Docs</a></nav>
          <div className="flex items-center gap-4"><Link to="/auth/login"><Button variant="ghost">Sign In</Button></Link><Link to="/auth/register"><Button>Get Started</Button></Link></div>
        </div>
      </header>
      <main>
        <section className="py-20 md:py-32">
          <div className="container mx-auto px-4 text-center">
            <Badge className="mb-4" variant="secondary">Now with QUIC & Minecraft Protection</Badge>
            <h1 className="text-4xl md:text-6xl font-bold tracking-tight mb-6">Enterprise DDoS Protection<br /><span className="text-primary">Powered by eBPF</span></h1>
            <p className="text-xl text-muted-foreground max-w-2xl mx-auto mb-8">Stop volumetric attacks before they overwhelm your infrastructure. Kernel-level XDP filtering provides unmatched protection with minimal latency.</p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center"><Link to="/auth/register"><Button size="lg">Start Free Trial<ArrowRight className="ml-2 h-4 w-4" /></Button></Link><Link to="/dashboard"><Button size="lg" variant="outline">View Dashboard</Button></Link></div>
            <div className="flex items-center justify-center gap-8 mt-12 text-sm text-muted-foreground">
              <div className="flex items-center gap-2"><Check className="h-4 w-4 text-green-500" />No credit card required</div>
              <div className="flex items-center gap-2"><Check className="h-4 w-4 text-green-500" />14-day free trial</div>
              <div className="flex items-center gap-2"><Check className="h-4 w-4 text-green-500" />Cancel anytime</div>
            </div>
          </div>
        </section>
        <section id="features" className="py-20 bg-muted/50">
          <div className="container mx-auto px-4">
            <div className="text-center mb-12"><h2 className="text-3xl font-bold mb-4">Built for Modern Infrastructure</h2><p className="text-muted-foreground max-w-2xl mx-auto">eBPF/XDP technology operates at the kernel level, providing protection that traditional solutions cannot match.</p></div>
            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">{features.map((f, i) => (<Card key={i}><CardHeader><f.icon className="h-10 w-10 text-primary mb-2" /><CardTitle>{f.title}</CardTitle></CardHeader><CardContent><CardDescription>{f.description}</CardDescription></CardContent></Card>))}</div>
          </div>
        </section>
        <section id="pricing" className="py-20">
          <div className="container mx-auto px-4">
            <div className="text-center mb-12"><h2 className="text-3xl font-bold mb-4">Simple, Transparent Pricing</h2><p className="text-muted-foreground">Choose the plan that fits your needs.</p></div>
            <div className="grid gap-6 md:grid-cols-3 max-w-5xl mx-auto">
              {plans.map((p, i) => (
                <Card key={i} className={p.popular ? "border-primary shadow-lg" : ""}>
                  <CardHeader>{p.popular && <Badge className="w-fit mb-2">Most Popular</Badge>}<CardTitle>{p.name}</CardTitle><CardDescription><span className="text-4xl font-bold">${p.price}</span>/month</CardDescription></CardHeader>
                  <CardContent className="space-y-4"><ul className="space-y-2">{p.features.map((f, j) => (<li key={j} className="flex items-center gap-2 text-sm"><Check className="h-4 w-4 text-green-500" />{f}</li>))}</ul><Button className="w-full" variant={p.popular ? "default" : "outline"}>{p.cta}</Button></CardContent>
                </Card>
              ))}
            </div>
          </div>
        </section>
      </main>
      <footer className="border-t py-12">
        <div className="container mx-auto px-4 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2"><Shield className="h-5 w-5 text-primary" /><span className="font-bold">PistonProtection</span></div>
          <div className="flex items-center gap-6 text-sm text-muted-foreground"><a href="#" className="hover:text-foreground">Privacy</a><a href="#" className="hover:text-foreground">Terms</a><a href="/docs" className="hover:text-foreground">Documentation</a></div>
          <p className="text-sm text-muted-foreground">© 2025 PistonProtection. All rights reserved.</p>
        </div>
      </footer>
    </div>
  )
}
