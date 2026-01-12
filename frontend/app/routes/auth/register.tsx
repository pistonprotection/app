import { createFileRoute, Link } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Shield, Github, Mail, Check } from "lucide-react";

export const Route = createFileRoute("/auth/register")({
  component: RegisterPage,
});

function RegisterPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="w-full max-w-md">
        <div className="flex flex-col items-center mb-8">
          <Link to="/" className="flex items-center gap-2 mb-4">
            <Shield className="h-10 w-10 text-primary" />
            <span className="text-2xl font-bold">PistonProtection</span>
          </Link>
          <p className="text-muted-foreground text-center">
            Create your account and start protecting your servers
          </p>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Create Account</CardTitle>
            <CardDescription>
              Get started with a free 14-day trial
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Social Signup */}
            <div className="grid gap-3">
              <Button variant="outline" className="w-full gap-2">
                <Github className="h-4 w-4" />
                Continue with GitHub
              </Button>
              <Button variant="outline" className="w-full gap-2">
                <Mail className="h-4 w-4" />
                Continue with Google
              </Button>
            </div>

            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <Separator />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-card px-2 text-muted-foreground">
                  Or continue with email
                </span>
              </div>
            </div>

            {/* Email Registration */}
            <form className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="firstName">First Name</Label>
                  <Input
                    id="firstName"
                    placeholder="John"
                    autoComplete="given-name"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="lastName">Last Name</Label>
                  <Input
                    id="lastName"
                    placeholder="Doe"
                    autoComplete="family-name"
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  type="email"
                  placeholder="name@example.com"
                  autoComplete="email"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  autoComplete="new-password"
                />
                <ul className="text-xs text-muted-foreground space-y-1 mt-2">
                  <li className="flex items-center gap-1">
                    <Check className="h-3 w-3" />
                    At least 8 characters
                  </li>
                  <li className="flex items-center gap-1">
                    <Check className="h-3 w-3" />
                    One uppercase letter
                  </li>
                  <li className="flex items-center gap-1">
                    <Check className="h-3 w-3" />
                    One number
                  </li>
                </ul>
              </div>
              <Button type="submit" className="w-full">
                Create Account
              </Button>
            </form>

            <p className="text-center text-sm text-muted-foreground">
              Already have an account?{" "}
              <Link
                to="/auth/login"
                className="text-primary hover:underline"
              >
                Sign in
              </Link>
            </p>
          </CardContent>
        </Card>

        <p className="mt-4 text-center text-xs text-muted-foreground">
          By creating an account, you agree to our{" "}
          <Link to="/" className="hover:underline">
            Terms of Service
          </Link>{" "}
          and{" "}
          <Link to="/" className="hover:underline">
            Privacy Policy
          </Link>
        </p>
      </div>
    </div>
  );
}
