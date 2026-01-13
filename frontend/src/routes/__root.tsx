import { AuthUIProvider } from "@daveyplate/better-auth-ui";
import { TanStackDevtools } from "@tanstack/react-devtools";
import { ReactQueryDevtools } from "@tanstack/react-query-devtools";
import {
  createRootRoute,
  HeadContent,
  Link,
  Outlet,
  Scripts,
  useRouter,
} from "@tanstack/react-router";
import { TanStackRouterDevtoolsPanel } from "@tanstack/react-router-devtools";
import { Toaster } from "sonner";
import { authClient } from "@/lib/auth-client";
import { TRPCReactProvider } from "@/lib/trpc/client";

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

function AuthProviderWrapper({ children }: { children: React.ReactNode }) {
  const router = useRouter();

  return (
    <AuthUIProvider
      authClient={authClient}
      navigate={(href) => {
        router.navigate({ to: href });
      }}
      replace={(href) => {
        router.navigate({ to: href, replace: true });
      }}
      onSessionChange={() => {
        router.invalidate();
      }}
      Link={(props) => {
        const { href, ...rest } = props;
        return <Link {...rest} to={href} />;
      }}
      social={{
        providers: ["google", "discord", "github"],
      }}
      emailOTP
      emailVerification
      changeEmail
      passkey
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
        pathMode: "slug",
        apiKey: true,
        basePath: "/dashboard/organization",
        personalPath: "/dashboard",
      }}
      account={{
        basePath: "/dashboard",
      }}
      localization={{
        NAME: "Display Name",
        NAME_DESCRIPTION: "Please enter a display name.",
        NAME_PLACEHOLDER: "Display Name",
      }}
    >
      {children}
    </AuthUIProvider>
  );
}

function RootDocument({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <head>
        <HeadContent />
      </head>
      <body className="min-h-screen bg-background font-sans antialiased">
        <TRPCReactProvider>
          <AuthProviderWrapper>
            {children}
            <Toaster position="top-right" richColors closeButton />
          </AuthProviderWrapper>
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
