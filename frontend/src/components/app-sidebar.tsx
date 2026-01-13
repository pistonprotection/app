import { Link, useLocation } from "@tanstack/react-router";
import {
  BarChart3,
  BookOpen,
  CreditCard,
  Filter,
  LayoutDashboard,
  LogOut,
  Search,
  Server,
  Settings,
  Shield,
} from "lucide-react";
import { OrganizationSwitcher } from "@/components/organization-switcher";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar";
import { authClient } from "@/lib/auth-client";

const menuItems = [
  { title: "Overview", url: "/dashboard", icon: LayoutDashboard },
  { title: "Setup Guide", url: "/dashboard/setup", icon: BookOpen },
  { title: "Backends", url: "/dashboard/backends", icon: Server },
  { title: "Filters", url: "/dashboard/filters", icon: Filter },
  { title: "Analytics", url: "/dashboard/analytics", icon: BarChart3 },
  { title: "IP Lookup", url: "/dashboard/ip-lookup", icon: Search },
  { title: "Settings", url: "/dashboard/settings", icon: Settings },
  { title: "Billing", url: "/dashboard/billing", icon: CreditCard },
];

export function AppSidebar() {
  const location = useLocation();
  const sidebar = useSidebar();

  const handleSignOut = async () => {
    await authClient.signOut();
    window.location.href = "/auth/login";
  };

  return (
    <Sidebar>
      <SidebarHeader className="border-b px-4 py-4">
        <Link to="/" className="flex items-center gap-2 mb-4">
          <Shield className="h-6 w-6 text-primary" />
          {sidebar.open && (
            <span className="font-bold text-lg">PistonProtection</span>
          )}
        </Link>
        <OrganizationSwitcher collapsed={!sidebar.open} />
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Navigation</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {menuItems.map((item) => (
                <SidebarMenuItem key={item.title}>
                  <SidebarMenuButton
                    render={<Link to={item.url} />}
                    isActive={
                      location.pathname === item.url ||
                      (item.url !== "/dashboard" &&
                        location.pathname.startsWith(item.url))
                    }
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
      <SidebarFooter className="border-t p-4">
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton onClick={handleSignOut}>
              <LogOut className="h-4 w-4" />
              <span>Sign Out</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>
  );
}
