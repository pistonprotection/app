import { passkeyClient } from "@better-auth/passkey/client";
import { stripeClient } from "@better-auth/stripe/client";
import {
  adminClient,
  apiKeyClient,
  emailOTPClient,
  inferAdditionalFields,
  inferOrgAdditionalFields,
  lastLoginMethodClient,
  oneTimeTokenClient,
  organizationClient,
  twoFactorClient,
  usernameClient,
} from "better-auth/client/plugins";
import { createAuthClient } from "better-auth/react";
import type { InferUserFromClient } from "better-auth/types";
import type { auth } from "@/server/auth";

// Global access control configuration
export const globalAc = {
  admin: ["admin"],
  user: ["user"],
} as const;

export const globalRoleConfig = {
  admin: {
    // Platform admin - full access
  },
  user: {
    // Regular user
  },
} as const;

// Organization access control configuration
export const orgAc = {
  owner: ["owner", "admin", "member"],
  admin: ["admin", "member"],
  member: ["member"],
} as const;

export const orgRoleConfig = {
  owner: {
    // Organization owner - full org control
  },
  admin: {
    // Organization admin - manage members and settings
  },
  member: {
    // Organization member - basic access
  },
} as const;

const clientOptions = {
  plugins: [
    inferAdditionalFields<typeof auth>(),
    twoFactorClient(),
    usernameClient(),
    emailOTPClient(),
    passkeyClient(),
    adminClient({
      ac: globalAc,
      roles: globalRoleConfig,
    }),
    apiKeyClient(),
    organizationClient({
      ac: orgAc,
      roles: orgRoleConfig,
      schema: inferOrgAdditionalFields<typeof auth>(),
    }),
    oneTimeTokenClient(),
    stripeClient({
      subscription: true,
    }),
    lastLoginMethodClient(),
  ],
};

export const authClient = createAuthClient(clientOptions);

export type AppUser = InferUserFromClient<typeof clientOptions>;
export type AppGlobalRole = keyof typeof globalRoleConfig;
export type AppOrgRole = keyof typeof orgRoleConfig;

export const appGlobalRoles = Object.keys(globalRoleConfig) as [
  AppGlobalRole,
  ...AppGlobalRole[],
];

export const appOrgRoles = Object.keys(orgRoleConfig) as [
  AppOrgRole,
  ...AppOrgRole[],
];
