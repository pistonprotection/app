import { createFileRoute, Link } from "@tanstack/react-router";
import { Shield } from "lucide-react";
import { Separator } from "@/components/ui/separator";

export const Route = createFileRoute("/terms")({
  component: TermsPage,
  head: () => ({
    meta: [
      { title: "Terms of Service - PistonProtection" },
      {
        name: "description",
        content:
          "PistonProtection terms of service. Read our terms and conditions for using our DDoS protection services.",
      },
    ],
  }),
});

function TermsPage() {
  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b">
        <div className="container mx-auto flex h-16 items-center px-4">
          <Link to="/" className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            <span className="font-bold text-lg">PistonProtection</span>
          </Link>
        </div>
      </header>

      <main className="container mx-auto px-4 py-12 max-w-4xl">
        <h1 className="text-4xl font-bold mb-4">Terms of Service</h1>
        <p className="text-muted-foreground mb-8">
          Last updated: {new Date().toLocaleDateString()}
        </p>

        <div className="prose prose-neutral dark:prose-invert max-w-none space-y-8">
          <section>
            <h2 className="text-2xl font-semibold mb-4">
              1. Acceptance of Terms
            </h2>
            <p className="text-muted-foreground leading-relaxed">
              By accessing or using PistonProtection's DDoS protection services
              ("Services"), you agree to be bound by these Terms of Service
              ("Terms"). If you do not agree to these Terms, do not use the
              Services.
            </p>
          </section>

          <Separator />

          <section>
            <h2 className="text-2xl font-semibold mb-4">
              2. Description of Services
            </h2>
            <p className="text-muted-foreground leading-relaxed">
              PistonProtection provides DDoS mitigation and traffic filtering
              services using eBPF/XDP technology. Services include traffic
              proxying, attack detection, rate limiting, and related features as
              described in your selected plan.
            </p>
          </section>

          <Separator />

          <section>
            <h2 className="text-2xl font-semibold mb-4">3. Acceptable Use</h2>
            <p className="text-muted-foreground leading-relaxed mb-4">
              You agree not to use our Services to:
            </p>
            <ul className="list-disc pl-6 space-y-2 text-muted-foreground">
              <li>Protect infrastructure used for illegal activities</li>
              <li>Host content that infringes intellectual property rights</li>
              <li>Distribute malware or engage in phishing</li>
              <li>Launch attacks against other networks</li>
              <li>Violate applicable laws or regulations</li>
              <li>Interfere with our Services or other users</li>
            </ul>
          </section>

          <Separator />

          <section>
            <h2 className="text-2xl font-semibold mb-4">
              4. Account Responsibilities
            </h2>
            <p className="text-muted-foreground leading-relaxed">
              You are responsible for maintaining the security of your account
              credentials, all activities under your account, and ensuring your
              backend servers comply with applicable laws. You must promptly
              notify us of any unauthorized access.
            </p>
          </section>

          <Separator />

          <section>
            <h2 className="text-2xl font-semibold mb-4">
              5. Service Availability
            </h2>
            <p className="text-muted-foreground leading-relaxed">
              We strive to maintain high availability but do not guarantee
              uninterrupted service. Planned maintenance will be announced in
              advance. Enterprise plans include SLA guarantees as specified in
              your service agreement.
            </p>
          </section>

          <Separator />

          <section>
            <h2 className="text-2xl font-semibold mb-4">
              6. Payment and Billing
            </h2>
            <p className="text-muted-foreground leading-relaxed">
              Paid plans are billed monthly or annually as selected. Prices are
              in USD unless otherwise specified. You authorize us to charge your
              payment method for all fees incurred. Overages are billed at
              published rates.
            </p>
          </section>

          <Separator />

          <section>
            <h2 className="text-2xl font-semibold mb-4">
              7. Limitation of Liability
            </h2>
            <p className="text-muted-foreground leading-relaxed">
              To the maximum extent permitted by law, PistonProtection shall not
              be liable for any indirect, incidental, special, consequential, or
              punitive damages, or any loss of profits, revenue, data, or
              business opportunities arising from your use of the Services.
            </p>
          </section>

          <Separator />

          <section>
            <h2 className="text-2xl font-semibold mb-4">8. Termination</h2>
            <p className="text-muted-foreground leading-relaxed">
              Either party may terminate the agreement at any time. We may
              suspend or terminate your access immediately for violations of
              these Terms. Upon termination, your right to use the Services
              ceases immediately.
            </p>
          </section>

          <Separator />

          <section>
            <h2 className="text-2xl font-semibold mb-4">9. Changes to Terms</h2>
            <p className="text-muted-foreground leading-relaxed">
              We may update these Terms from time to time. Material changes will
              be communicated via email or dashboard notification. Continued use
              after changes constitutes acceptance of the updated Terms.
            </p>
          </section>

          <Separator />

          <section>
            <h2 className="text-2xl font-semibold mb-4">10. Contact</h2>
            <p className="text-muted-foreground leading-relaxed">
              For questions about these Terms, contact us at{" "}
              <a
                href="mailto:legal@pistonprotection.com"
                className="text-primary hover:underline"
              >
                legal@pistonprotection.com
              </a>{" "}
              or through our GitHub repository.
            </p>
          </section>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t py-8 mt-16">
        <div className="container mx-auto px-4 text-center text-sm text-muted-foreground">
          <p>
            &copy; {new Date().getFullYear()} PistonProtection. All rights
            reserved.
          </p>
        </div>
      </footer>
    </div>
  );
}
