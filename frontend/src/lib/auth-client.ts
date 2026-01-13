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
import { createAccessControl } from "better-auth/plugins/access";
import {
  adminAc as defaultGlobalAdminAc,
  defaultStatements as defaultGlobalStatements,
  userAc as defaultGlobalUserAc,
} from "better-auth/plugins/admin/access";
import {
  adminAc as defaultOrgAdminAc,
  memberAc as defaultOrgMemberAc,
  ownerAc as defaultOrgOwnerAc,
  defaultStatements as defaultOrgStatements,
} from "better-auth/plugins/organization/access";
import { createAuthClient } from "better-auth/react";
import type { InferUserFromClient } from "better-auth/types";
import type { auth } from "@/server/auth";

// Global access control configuration
export const globalAc = createAccessControl({
  ...defaultGlobalStatements,
  organization: ["create"],
});

export const globalUser = globalAc.newRole({
  ...defaultGlobalUserAc.statements,
  organization: ["create"],
});

export const globalAdmin = globalAc.newRole({
  ...globalUser.statements,
  ...defaultGlobalAdminAc.statements,
});

export const globalRoleConfig = {
  admin: globalAdmin,
  user: globalUser,
};

// Organization access control configuration
export const orgAc = createAccessControl({
  ...defaultOrgStatements,
});

export const orgMember = orgAc.newRole({
  ...defaultOrgMemberAc.statements,
});

export const orgAdmin = orgAc.newRole({
  ...orgMember.statements,
  ...defaultOrgAdminAc.statements,
});

export const orgOwner = orgAc.newRole({
  ...orgAdmin.statements,
  ...defaultOrgOwnerAc.statements,
});

export const orgRoleConfig = {
  owner: orgOwner,
  admin: orgAdmin,
  member: orgMember,
};

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
