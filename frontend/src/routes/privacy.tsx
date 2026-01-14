import { createFileRoute, Link } from "@tanstack/react-router";
import { Shield } from "lucide-react";
import { Separator } from "@/components/ui/separator";

export const Route = createFileRoute("/privacy")({
  component: PrivacyPage,
  head: () => ({
    meta: [
      { title: "Privacy Policy - PistonProtection" },
      {
        name: "description",
        content:
          "PistonProtection privacy policy. Learn how we collect, use, and protect your data.",
      },
    ],
  }),
});

function PrivacyPage() {
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
        <h1 className="text-4xl font-bold mb-4">Privacy Policy</h1>
        <p className="text-muted-foreground mb-8">
          Last updated: {new Date().toLocaleDateString()}
        </p>

        <div className="prose prose-neutral dark:prose-invert max-w-none space-y-8">
          <section>
            <h2 className="text-2xl font-semibold mb-4">1. Introduction</h2>
            <p className="text-muted-foreground leading-relaxed">
              PistonProtection ("we", "our", or "us") is committed to protecting
              your privacy. This Privacy Policy explains how we collect, use,
              disclose, and safeguard your information when you use our DDoS
              protection services and website.
            </p>
          </section>

          <Separator />

          <section>
            <h2 className="text-2xl font-semibold mb-4">
              2. Information We Collect
            </h2>
            <h3 className="text-lg font-medium mb-2">Account Information</h3>
            <p className="text-muted-foreground leading-relaxed mb-4">
              When you create an account, we collect your email address, name,
              and organization details. If you use OAuth providers, we receive
              basic profile information from those services.
            </p>
            <h3 className="text-lg font-medium mb-2">Traffic Data</h3>
            <p className="text-muted-foreground leading-relaxed mb-4">
              To provide DDoS protection, we process network traffic metadata
              including IP addresses, packet headers, request patterns, and
              connection information. This data is used solely for traffic
              analysis and attack mitigation.
            </p>
            <h3 className="text-lg font-medium mb-2">Usage Data</h3>
            <p className="text-muted-foreground leading-relaxed">
              We collect information about how you use our services, including
              dashboard interactions, API calls, and feature usage for service
              improvement.
            </p>
          </section>

          <Separator />

          <section>
            <h2 className="text-2xl font-semibold mb-4">
              3. How We Use Your Information
            </h2>
            <ul className="list-disc pl-6 space-y-2 text-muted-foreground">
              <li>Provide and maintain our DDoS protection services</li>
              <li>
                Detect, prevent, and mitigate attacks on your infrastructure
              </li>
              <li>Send service notifications and security alerts</li>
              <li>Process payments and manage billing</li>
              <li>Improve our services and develop new features</li>
              <li>Respond to your requests and provide support</li>
              <li>Comply with legal obligations</li>
            </ul>
          </section>

          <Separator />

          <section>
            <h2 className="text-2xl font-semibold mb-4">4. Data Retention</h2>
            <p className="text-muted-foreground leading-relaxed">
              Traffic logs and attack data are retained according to your plan's
              retention period (7-90 days). Account information is retained
              while your account is active and for a reasonable period afterward
              for legal and business purposes.
            </p>
          </section>

          <Separator />

          <section>
            <h2 className="text-2xl font-semibold mb-4">5. Data Security</h2>
            <p className="text-muted-foreground leading-relaxed">
              We implement industry-standard security measures including
              encryption in transit (TLS 1.3), encryption at rest, access
              controls, and regular security audits. Our infrastructure is
              designed with security as a core principle.
            </p>
          </section>

          <Separator />

          <section>
            <h2 className="text-2xl font-semibold mb-4">6. Your Rights</h2>
            <p className="text-muted-foreground leading-relaxed mb-4">
              Depending on your jurisdiction, you may have rights to access,
              correct, delete, or export your personal data. You can manage most
              settings through your dashboard or contact us for assistance.
            </p>
          </section>

          <Separator />

          <section>
            <h2 className="text-2xl font-semibold mb-4">7. Contact Us</h2>
            <p className="text-muted-foreground leading-relaxed">
              If you have questions about this Privacy Policy, please contact us
              at{" "}
              <a
                href="mailto:privacy@pistonprotection.com"
                className="text-primary hover:underline"
              >
                privacy@pistonprotection.com
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
