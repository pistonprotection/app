import { HeadContent, Outlet, Scripts, createRootRoute } from "@tanstack/react-router";
import { TanStackRouterDevtoolsPanel } from "@tanstack/react-router-devtools";
import { TanStackDevtools } from "@tanstack/react-devtools";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";
import { Toaster } from "sonner";
import { TRPCReactProvider } from "@/lib/trpc/client";
import { AuthUIProvider } from "@daveyplate/better-auth-ui";
import { authClient } from "@/lib/auth-client";

import appCss from "../styles.css?url";
import "@fontsource-variable/inter";

export const Route = createRootRoute({
  head: () => ({
    meta: [
      {
        charSet: "utf-8",
      },
      {
        name: "viewport",
        content: "width=device-width, initial-scale=1",
      },
      {
        title: "PistonProtection - Enterprise DDoS Protection Platform",
      },
      {
        name: "description",
        content:
          "Enterprise-grade, self-hostable DDoS protection with eBPF/XDP filtering. Protect your servers from Layer 4 and Layer 7 attacks.",
      },
    ],
    links: [
      {
        rel: "stylesheet",
        href: appCss,
      },
      {
        rel: "icon",
        href: "/favicon.ico",
      },
    ],
  }),
  component: RootComponent,
});

function RootComponent() {
  return (
    <RootDocument>
      <Outlet />
    </RootDocument>
  );
}

function RootDocument({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <head>
        <HeadContent />
      </head>
      <body className="min-h-screen bg-background font-sans antialiased">
        <TRPCReactProvider>
          <AuthUIProvider
            authClient={authClient}
            navigate={(href) => {
              window.location.href = href;
            }}
            replace={(href) => {
              window.location.replace(href);
            }}
            onSessionChange={() => {
              window.location.reload();
            }}
            emailOTP
            emailVerification
            changeEmail
            deleteUser={{
              verification: true,
            }}
            credentials={{
              forgotPassword: true,
              username: true,
            }}
            signUp
            nameRequired={false}
            apiKey
            optimistic
            twoFactor={["otp", "totp"]}
            redirectTo="/dashboard"
            organization={{
              apiKey: true,
              basePath: "/dashboard/organization",
              personalPath: "/dashboard",
            }}
            account={{
              basePath: "/dashboard",
            }}
          >
            {children}
            <Toaster position="top-right" richColors closeButton />
          </AuthUIProvider>
        </TRPCReactProvider>
        <TanStackDevtools
          config={{
            position: "bottom-right",
          }}
          plugins={[
            {
              name: "TanStack Router",
              render: <TanStackRouterDevtoolsPanel />,
            },
          ]}
        />
        <ReactQueryDevtools initialIsOpen={false} />
        <Scripts />
      </body>
    </html>
  );
}
