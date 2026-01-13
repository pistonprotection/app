import {
  createFileRoute,
  Link,
  Outlet,
  redirect,
  useLocation,
} from "@tanstack/react-router";
import {
  Activity,
  AlertTriangle,
  Ban,
  Building2,
  History,
  LayoutDashboard,
  Server,
  Settings,
  Shield,
  UserCog,
} from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import { auth } from "@/server/auth";

export const Route = createFileRoute("/admin/")({
  beforeLoad: async ({ context }) => {
    // Server-side session and admin role check
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

    if (session.user.role !== "admin") {
      throw redirect({
        to: "/dashboard",
      });
    }

    return { session };
  },
  component: AdminLayout,
});

const adminNavItems = [
  {
    title: "Overview",
    href: "/admin",
    icon: LayoutDashboard,
  },
  {
    title: "Organizations",
    href: "/admin/organizations",
    icon: Building2,
  },
  {
    title: "Users",
    href: "/admin/users",
    icon: UserCog,
  },
  {
    title: "Backends",
    href: "/admin/backends",
    icon: Server,
  },
  {
    title: "Blacklists",
    href: "/admin/blacklists",
    icon: Ban,
  },
  {
    title: "Attacks",
    href: "/admin/attacks",
    icon: AlertTriangle,
  },
  {
    title: "Metrics",
    href: "/admin/metrics",
    icon: Activity,
  },
  {
    title: "Audit Log",
    href: "/admin/audit-log",
    icon: History,
  },
  {
    title: "Settings",
    href: "/admin/settings",
    icon: Settings,
  },
];

function AdminLayout() {
  // Session is already verified in beforeLoad
  const location = useLocation();

  return (
    <SidebarProvider>
      <div className="min-h-screen flex w-full">
        <Sidebar>
          <SidebarContent>
            <SidebarGroup>
              <SidebarGroupLabel>
                <div className="flex items-center gap-2">
                  <Shield className="h-5 w-5 text-primary" />
                  <span className="font-semibold">Admin Panel</span>
                </div>
              </SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {adminNavItems.map((item) => (
                    <SidebarMenuItem key={item.href}>
                      <SidebarMenuButton
                        render={<Link to={item.href} />}
                        isActive={location.pathname === item.href}
                      >
                        <item.icon className="h-4 w-4" />
                        <span>{item.title}</span>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  ))}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </SidebarContent>
        </Sidebar>
        <main className="flex-1 p-6">
          <div className="mb-4">
            <SidebarTrigger />
          </div>
          <Outlet />
        </main>
      </div>
    </SidebarProvider>
  );
}
