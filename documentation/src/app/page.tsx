import Link from 'next/link';

export default function HomePage() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-8 bg-gradient-to-b from-background to-muted">
      <div className="text-center space-y-6 max-w-3xl">
        <h1 className="text-5xl font-bold tracking-tight">
          PistonProtection
        </h1>
        <p className="text-xl text-muted-foreground">
          Enterprise-grade DDoS protection powered by eBPF/XDP technology.
          Protect your infrastructure with sub-millisecond packet filtering.
        </p>
        <div className="flex gap-4 justify-center">
          <Link
            href="/docs"
            className="inline-flex items-center justify-center rounded-md bg-primary px-6 py-3 text-sm font-medium text-primary-foreground shadow hover:bg-primary/90"
          >
            Get Started
          </Link>
          <Link
            href="/docs/api"
            className="inline-flex items-center justify-center rounded-md border border-input bg-background px-6 py-3 text-sm font-medium shadow-sm hover:bg-accent hover:text-accent-foreground"
          >
            API Reference
          </Link>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-12 text-left">
          <div className="p-6 rounded-lg border bg-card">
            <h3 className="font-semibold mb-2">High Performance</h3>
            <p className="text-sm text-muted-foreground">
              XDP filters process packets before they reach the kernel network stack, achieving millions of packets per second.
            </p>
          </div>
          <div className="p-6 rounded-lg border bg-card">
            <h3 className="font-semibold mb-2">Protocol Aware</h3>
            <p className="text-sm text-muted-foreground">
              Deep packet inspection for TCP, UDP, QUIC, HTTP, and Minecraft protocols with intelligent filtering.
            </p>
          </div>
          <div className="p-6 rounded-lg border bg-card">
            <h3 className="font-semibold mb-2">Kubernetes Native</h3>
            <p className="text-sm text-muted-foreground">
              Deploy with Helm, scale with operators, and integrate with Cilium for complete network security.
            </p>
          </div>
        </div>
      </div>
    </main>
  );
}
