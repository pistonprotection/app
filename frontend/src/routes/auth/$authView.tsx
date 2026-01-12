import { AuthView } from "@daveyplate/better-auth-ui";
import { createFileRoute, Link } from "@tanstack/react-router";
import { Shield } from "lucide-react";

export const Route = createFileRoute("/auth/$authView")({
  component: AuthPage,
});

function AuthPage() {
  const { authView } = Route.useParams();

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="w-full max-w-md space-y-8">
        <div className="flex flex-col items-center text-center">
          <Link to="/" className="flex items-center gap-2 mb-4">
            <Shield className="h-10 w-10 text-primary" />
            <span className="text-2xl font-bold">PistonProtection</span>
          </Link>
        </div>
        <AuthView pathname={authView} />
      </div>
    </div>
  );
}
