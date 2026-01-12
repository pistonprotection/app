import { stripe } from "@better-auth/stripe";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import {
  admin,
  apiKey,
  emailOTP,
  haveIBeenPwned,
  jwt,
  oneTimeToken,
  openAPI,
  organization,
  twoFactor,
  username,
} from "better-auth/plugins";
import { emailHarmony } from "better-auth-harmony";
import { eq } from "drizzle-orm";
import { env } from "@/env";
import { authNotifications } from "@/server/auth-notifications";
import { db } from "@/server/db";
import * as authSchema from "@/server/db/auth-schema";
import * as appSchema from "@/server/db/schema";
import { getRoleOfUserInOrg, protectionPlans } from "@/server/server-utils";
import { handleStripeEvent, stripeClient } from "@/server/stripe";

const siteName = "PistonProtection";
const baseUrlString = env.PUBLIC_APP_URL;

function emailToUniqueUsername(email: string): string {
  const prefix = email.split("@")[0].replace(/[^a-zA-Z0-9_]/g, "");
  const suffix = Math.random().toString(36).substring(2, 8);
  return `${prefix}_${suffix}`;
}

export const auth = betterAuth({
  appName: siteName,
  baseURL: baseUrlString,
  secret: env.BETTER_AUTH_SECRET,
  database: drizzleAdapter(db, {
    provider: "pg",
    schema: {
      ...authSchema,
      ...appSchema,
    },
  }),
  advanced: {
    ipAddress: {
      ipAddressHeaders: ["cf-connecting-ip", "x-forwarded-for"],
    },
    database: {
      generateId: "uuid",
      experimentalJoins: true,
    },
  },
  account: {
    accountLinking: {
      enabled: true,
    },
  },
  socialProviders: {
    ...(env.PUBLIC_GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET
      ? {
          google: {
            clientId: env.PUBLIC_GOOGLE_CLIENT_ID,
            clientSecret: env.GOOGLE_CLIENT_SECRET,
          },
        }
      : {}),
    ...(env.PUBLIC_GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET
      ? {
          github: {
            clientId: env.PUBLIC_GITHUB_CLIENT_ID,
            clientSecret: env.GITHUB_CLIENT_SECRET,
          },
        }
      : {}),
    ...(env.PUBLIC_DISCORD_CLIENT_ID && env.DISCORD_CLIENT_SECRET
      ? {
          discord: {
            clientId: env.PUBLIC_DISCORD_CLIENT_ID,
            clientSecret: env.DISCORD_CLIENT_SECRET,
          },
        }
      : {}),
  },
  databaseHooks: {
    user: {
      create: {
        before: async (user) => {
          const customTypedUser = user as unknown as typeof user & {
            username?: string;
            displayUsername?: string;
          };
          const uniqueUsername = emailToUniqueUsername(user.email);

          return {
            data: {
              ...user,
              username: customTypedUser.username ?? uniqueUsername,
              displayUsername:
                customTypedUser.displayUsername ?? uniqueUsername,
            },
          };
        },
        after: async (userParam) => {
          await db
            .update(authSchema.user)
            .set({
              theme: "system",
            })
            .where(eq(authSchema.user.id, userParam.id));
        },
      },
    },
  },
  emailAndPassword: {
    enabled: true,
    requireEmailVerification: true,
    async sendResetPassword({ user, url }): Promise<void> {
      await authNotifications.sendPasswordReset({ user, url });
    },
    autoSignIn: true,
  },
  emailVerification: {
    async sendVerificationEmail({ user, url }): Promise<void> {
      await authNotifications.sendEmailVerification({ user, url });
    },
    sendOnSignUp: true,
    sendOnSignIn: true,
    autoSignInAfterVerification: true,
  },
  user: {
    changeEmail: {
      enabled: true,
      async sendChangeEmailVerification({ user, url }): Promise<void> {
        await authNotifications.sendChangeEmailVerification({ user, url });
      },
    },
    deleteUser: {
      enabled: true,
      async sendDeleteAccountVerification({ user, url }): Promise<void> {
        await authNotifications.sendDeleteAccountVerification({ user, url });
      },
    },
    additionalFields: {
      theme: {
        type: "string",
        input: false,
      },
    },
  },
  plugins: [
    emailHarmony(),
    twoFactor({
      otpOptions: {
        async sendOTP({ user, otp }): Promise<void> {
          await authNotifications.sendTwoFactorOTP({ user, otp });
        },
      },
    }),
    username(),
    emailOTP({
      sendVerificationOnSignUp: false,
      async sendVerificationOTP({ email, otp, type }): Promise<void> {
        await authNotifications.sendEmailOTP({ email, otp, type });
      },
    }),
    admin({
      ac: {
        admin: ["admin"],
        user: ["user"],
      },
      roles: {
        admin: {
          // Platform admin capabilities
        },
        user: {
          // Regular user capabilities
        },
      },
    }),
    apiKey({
      requireName: true,
      enableMetadata: true,
      defaultPrefix: "pp_",
    }),
    organization({
      ac: {
        owner: ["owner", "admin", "member"],
        admin: ["admin", "member"],
        member: ["member"],
      },
      roles: {
        owner: {},
        admin: {},
        member: {},
      },
      allowUserToCreateOrganization: async (_user): Promise<boolean> => {
        // Allow all verified users to create organizations
        return true;
      },
      cancelPendingInvitationsOnReInvite: true,
      async sendInvitationEmail({
        id,
        role,
        email,
        inviter,
        organization,
      }): Promise<void> {
        await authNotifications.sendOrganizationInvitation({
          id,
          role,
          email,
          inviter,
          organization,
        });
      },
    }),
    oneTimeToken(),
    openAPI(),
    haveIBeenPwned({
      customPasswordCompromisedMessage: "Please choose a more secure password.",
    }),
    jwt(),
    stripe({
      stripeClient: stripeClient,
      stripeWebhookSecret: env.STRIPE_WEBHOOK_SECRET,
      createCustomerOnSignUp: true,
      subscription: {
        enabled: true,
        plans: protectionPlans,
        requireEmailVerification: true,
        organization: {
          enabled: true,
        },
        authorizeReference: async ({
          user,
          referenceId,
          action,
        }): Promise<boolean> => {
          switch (action) {
            case "list-subscription":
              return true;
            case "upgrade-subscription":
            case "cancel-subscription":
            case "restore-subscription":
            case "billing-portal":
              return (
                (await getRoleOfUserInOrg(user.id, referenceId)) === "owner"
              );
            default:
              return false;
          }
        },
        getCheckoutSessionParams: async ({
          user,
          session: _session,
          plan,
          subscription: _subscription,
        }) => {
          return {
            params: {
              allow_promotion_codes: true,
              tax_id_collection: {
                enabled: true,
              },
              automatic_tax: {
                enabled: true,
              },
              billing_address_collection: "required",
              custom_text: {
                submit: {
                  message:
                    "Your DDoS protection will be activated immediately after payment.",
                },
              },
            },
            options: {
              idempotencyKey: `sub_${user.id}_${plan.name}_${Date.now()}`,
            },
          };
        },
        onSubscriptionComplete: async ({ subscription, plan }) => {
          const { stripeCustomerId } = subscription;
          if (!stripeCustomerId) {
            throw new Error("Subscription does not have a Stripe customer id");
          }

          const dbUser = await db.query.user.findFirst({
            where: (user, { eq }) =>
              eq(user.stripeCustomerId, stripeCustomerId),
          });
          if (!dbUser) {
            throw new Error("User not found for the given Stripe customer id");
          }

          await authNotifications.sendWelcomeEmail(dbUser.email, plan.name);
        },
        onSubscriptionUpdate: async ({ subscription }) => {
          console.log(`Subscription ${subscription.id} updated`);
        },
        onSubscriptionCancel: async ({ subscription }) => {
          const { stripeCustomerId } = subscription;
          if (!stripeCustomerId) {
            throw new Error("Subscription does not have a Stripe customer id");
          }

          const dbUser = await db.query.user.findFirst({
            where: (user, { eq }) =>
              eq(user.stripeCustomerId, stripeCustomerId),
          });
          if (!dbUser) {
            throw new Error("User not found for the given Stripe customer id");
          }

          await authNotifications.sendCancellationEmail(dbUser.email);
        },
        onSubscriptionDeleted: async ({ subscription }) => {
          console.log(`Subscription ${subscription.id} deleted`);
        },
      },
      onEvent: handleStripeEvent,
    }),
  ],
});

export type Session = typeof auth.$Infer.Session;
export type Organization = typeof auth.$Infer.Organization;
export type Member = typeof auth.$Infer.Member;
export type Invitation = typeof auth.$Infer.Invitation;
