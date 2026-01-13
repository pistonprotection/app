import { createFileRoute, Outlet, redirect } from "@tanstack/react-router";
import { AppSidebar } from "@/components/app-sidebar";
import { Separator } from "@/components/ui/separator";
import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import { OrganizationProvider } from "@/hooks/use-organization";
import { auth } from "@/server/auth";

export const Route = createFileRoute("/dashboard")({
  beforeLoad: async ({ context }) => {
    // Server-side session check for protected routes
    // Access request from context (set by TanStack Start during SSR)
    const ctx = context as { request?: Request };
    const session = await auth.api.getSession({
      headers: ctx.request?.headers ?? new Headers(),
    });

    if (!session?.user) {
      throw redirect({
        to: "/auth/$authView",
        params: { authView: "sign-in" },
      });
    }

    return { session };
  },
  component: DashboardLayout,
});

function DashboardLayout() {
  return (
    <OrganizationProvider>
      <SidebarProvider>
        <AppSidebar />
        <SidebarInset>
          <header className="flex h-14 shrink-0 items-center gap-2 border-b px-4">
            <SidebarTrigger className="-ml-1" />
            <Separator orientation="vertical" className="mr-2 h-4" />
            <span className="font-medium">PistonProtection</span>
          </header>
          <main className="flex-1 overflow-auto p-4">
            <Outlet />
          </main>
        </SidebarInset>
      </SidebarProvider>
    </OrganizationProvider>
  );
}
