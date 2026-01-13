import { eq } from "drizzle-orm";
import Stripe from "stripe";
import { env } from "@/env";
import { db } from "@/server/db";
import * as authSchema from "@/server/db/auth-schema";
import * as appSchema from "@/server/db/schema";
import { sendEmail } from "@/server/email";

export const stripeClient = new Stripe(env.STRIPE_SECRET_KEY, {
  apiVersion: "2025-12-15.clover",
});

// Get user by Stripe customer ID
async function getUserByStripeCustomerId(
  customerId: string,
): Promise<typeof authSchema.user.$inferSelect | null> {
  const dbUser = await db.query.user.findFirst({
    where: (user, { eq }) => eq(user.stripeCustomerId, customerId),
  });
  return dbUser ?? null;
}

// Send payment failed notification
async function sendPaymentFailedNotification(
  userEmail: string,
  invoiceId: string,
  amountDue: number,
): Promise<void> {
  const amountFormatted = new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
  }).format(amountDue / 100);

  await sendEmail(
    "PistonProtection Billing <billing@pistonprotection.com>",
    userEmail,
    "PistonProtection Support <support@pistonprotection.com>",
    "Payment Failed - Action Required",
    `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f4f4f5; margin: 0; padding: 20px;">
  <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; padding: 40px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
    <h1 style="color: #18181b; font-size: 24px; margin-bottom: 16px;">Payment Failed</h1>
    <p style="color: #71717a; font-size: 16px; line-height: 1.6; margin-bottom: 24px;">
      We were unable to process your payment of ${amountFormatted} for your PistonProtection subscription.
    </p>
    <p style="color: #71717a; font-size: 16px; line-height: 1.6; margin-bottom: 24px;">
      Please update your payment method to avoid service interruption. Your DDoS protection will remain active for a grace period, but will be suspended if payment is not received.
    </p>
    <a href="${env.PUBLIC_APP_URL}/dashboard/billing" style="display: inline-block; background-color: #3b82f6; color: white; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 500;">
      Update Payment Method
    </a>
    <p style="color: #a1a1aa; font-size: 14px; margin-top: 32px;">
      Invoice ID: ${invoiceId}
    </p>
  </div>
</body>
</html>
    `,
  );
}

// Send trial ending notification
async function sendTrialEndingNotification(
  userEmail: string,
  daysRemaining: number,
): Promise<void> {
  await sendEmail(
    "PistonProtection <noreply@pistonprotection.com>",
    userEmail,
    "PistonProtection Support <support@pistonprotection.com>",
    `Your trial ends in ${daysRemaining} days`,
    `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f4f4f5; margin: 0; padding: 20px;">
  <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; padding: 40px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
    <h1 style="color: #18181b; font-size: 24px; margin-bottom: 16px;">Your Trial is Ending Soon</h1>
    <p style="color: #71717a; font-size: 16px; line-height: 1.6; margin-bottom: 24px;">
      Your PistonProtection trial ends in ${daysRemaining} days. After that, your subscription will automatically convert to a paid plan.
    </p>
    <p style="color: #71717a; font-size: 16px; line-height: 1.6; margin-bottom: 24px;">
      If you'd like to continue protecting your servers from DDoS attacks, no action is needed - your service will continue uninterrupted.
    </p>
    <p style="color: #71717a; font-size: 16px; line-height: 1.6; margin-bottom: 24px;">
      If you'd like to cancel or change your plan, you can do so from your dashboard.
    </p>
    <a href="${env.PUBLIC_APP_URL}/dashboard/billing" style="display: inline-block; background-color: #3b82f6; color: white; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 500;">
      Manage Subscription
    </a>
  </div>
</body>
</html>
    `,
  );
}

// Send payment success notification
async function sendPaymentSuccessNotification(
  userEmail: string,
  amountPaid: number,
  invoiceUrl: string | null,
): Promise<void> {
  const amountFormatted = new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
  }).format(amountPaid / 100);

  await sendEmail(
    "PistonProtection Billing <billing@pistonprotection.com>",
    userEmail,
    "PistonProtection Support <support@pistonprotection.com>",
    "Payment Received - Thank You!",
    `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f4f4f5; margin: 0; padding: 20px;">
  <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; padding: 40px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
    <h1 style="color: #18181b; font-size: 24px; margin-bottom: 16px;">Payment Received</h1>
    <p style="color: #71717a; font-size: 16px; line-height: 1.6; margin-bottom: 24px;">
      Thank you! We've successfully processed your payment of ${amountFormatted}.
    </p>
    <p style="color: #71717a; font-size: 16px; line-height: 1.6; margin-bottom: 24px;">
      Your DDoS protection services will continue without interruption.
    </p>
    ${
      invoiceUrl
        ? `<a href="${invoiceUrl}" style="display: inline-block; background-color: #3b82f6; color: white; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 500;">
      View Invoice
    </a>`
        : ""
    }
  </div>
</body>
</html>
    `,
  );
}

// Log billing event for audit trail
async function logBillingEvent(
  organizationId: string | null,
  eventType: string,
  eventData: Record<string, unknown>,
): Promise<void> {
  if (!organizationId) return;

  await db.insert(appSchema.auditLog).values({
    organizationId,
    userId: null,
    action: `billing.${eventType}`,
    resource: "subscription",
    resourceId: eventData.subscriptionId as string | null,
    newValue: eventData,
    ipAddress: null,
    userAgent: "stripe-webhook",
  });
}

// Handle Stripe webhook events
export async function handleStripeEvent(event: Stripe.Event): Promise<void> {
  try {
    switch (event.type) {
      case "customer.subscription.created": {
        const subscription = event.data.object as Stripe.Subscription;
        console.log(
          `[Stripe Webhook] Subscription created: ${subscription.id}`,
        );

        // Log the event
        const referenceId =
          (subscription.metadata.referenceId as string) ?? null;
        await logBillingEvent(referenceId, "subscription_created", {
          subscriptionId: subscription.id,
          customerId: subscription.customer as string,
          status: subscription.status,
          plan: subscription.items.data[0]?.price?.lookup_key ?? "unknown",
        });
        break;
      }

      case "customer.subscription.updated": {
        const subscription = event.data.object as Stripe.Subscription;
        console.log(
          `[Stripe Webhook] Subscription updated: ${subscription.id}`,
        );

        // Get period info from subscription items in the new API
        const subscriptionItem = subscription.items.data[0];
        const periodStart = subscriptionItem?.current_period_start;
        const periodEnd = subscriptionItem?.current_period_end;

        // Update the subscription status in database
        await db
          .update(authSchema.subscription)
          .set({
            status: subscription.status,
            cancelAtPeriodEnd: subscription.cancel_at_period_end,
            periodStart: periodStart
              ? new Date(periodStart * 1000)
              : null,
            periodEnd: periodEnd
              ? new Date(periodEnd * 1000)
              : null,
          })
          .where(
            eq(authSchema.subscription.stripeSubscriptionId, subscription.id),
          );

        // Log the event
        const referenceId =
          (subscription.metadata.referenceId as string) ?? null;
        await logBillingEvent(referenceId, "subscription_updated", {
          subscriptionId: subscription.id,
          customerId: subscription.customer as string,
          status: subscription.status,
          cancelAtPeriodEnd: subscription.cancel_at_period_end,
        });
        break;
      }

      case "customer.subscription.deleted": {
        const subscription = event.data.object as Stripe.Subscription;
        console.log(
          `[Stripe Webhook] Subscription deleted: ${subscription.id}`,
        );

        // Update subscription status to canceled
        await db
          .update(authSchema.subscription)
          .set({
            status: "canceled",
          })
          .where(
            eq(authSchema.subscription.stripeSubscriptionId, subscription.id),
          );

        // Reset organization limits to free tier
        const referenceId = subscription.metadata.referenceId as string | null;
        if (referenceId) {
          await db
            .update(appSchema.protectionOrganization)
            .set({
              backendsLimit: 1,
              filtersLimit: 5,
              bandwidthLimit: 1_073_741_824, // 1GB
              billingType: "flat",
            })
            .where(
              eq(appSchema.protectionOrganization.organizationId, referenceId),
            );

          await logBillingEvent(referenceId, "subscription_deleted", {
            subscriptionId: subscription.id,
            customerId: subscription.customer as string,
          });
        }
        break;
      }

      case "invoice.payment_succeeded": {
        const invoice = event.data.object as Stripe.Invoice;
        console.log(`[Stripe Webhook] Payment succeeded: ${invoice.id}`);

        // Get user and send notification
        const customerId = invoice.customer as string;
        const user = await getUserByStripeCustomerId(customerId);

        if (user && invoice.amount_paid > 0) {
          await sendPaymentSuccessNotification(
            user.email,
            invoice.amount_paid,
            invoice.hosted_invoice_url ?? null,
          );
        }

        // Reset usage counters on successful billing cycle
        // In newer Stripe API, subscription is accessed via parent.subscription_details
        const parentSub = invoice.parent?.subscription_details;
        const subscriptionId = (parentSub?.subscription as string | null) ?? null;
        if (subscriptionId) {
          const sub = await db.query.subscription.findFirst({
            where: (s, { eq }) => eq(s.stripeSubscriptionId, subscriptionId),
          });

          if (sub?.referenceId) {
            await db
              .update(appSchema.protectionOrganization)
              .set({
                bandwidthUsed: 0,
                requestsUsed: 0,
              })
              .where(
                eq(
                  appSchema.protectionOrganization.organizationId,
                  sub.referenceId,
                ),
              );

            await logBillingEvent(sub.referenceId, "payment_succeeded", {
              invoiceId: invoice.id,
              amountPaid: invoice.amount_paid,
              subscriptionId,
            });
          }
        }
        break;
      }

      case "invoice.payment_failed": {
        const invoice = event.data.object as Stripe.Invoice;
        console.log(`[Stripe Webhook] Payment failed: ${invoice.id}`);

        // Get user and send notification
        const customerId = invoice.customer as string;
        const user = await getUserByStripeCustomerId(customerId);

        if (user) {
          await sendPaymentFailedNotification(
            user.email,
            invoice.id,
            invoice.amount_due,
          );
        }

        // Log the event
        // In newer Stripe API, subscription is accessed via parent.subscription_details
        const parentSubFailed = invoice.parent?.subscription_details;
        const subscriptionIdFailed = (parentSubFailed?.subscription as string | null) ?? null;
        if (subscriptionIdFailed) {
          const sub = await db.query.subscription.findFirst({
            where: (s, { eq }) => eq(s.stripeSubscriptionId, subscriptionIdFailed),
          });

          if (sub?.referenceId) {
            await logBillingEvent(sub.referenceId, "payment_failed", {
              invoiceId: invoice.id,
              amountDue: invoice.amount_due,
              subscriptionId: subscriptionIdFailed,
              attemptCount: invoice.attempt_count,
            });
          }
        }
        break;
      }

      case "customer.subscription.trial_will_end": {
        const subscription = event.data.object as Stripe.Subscription;
        console.log(`[Stripe Webhook] Trial will end: ${subscription.id}`);

        // Get user and send notification
        const customerId = subscription.customer as string;
        const user = await getUserByStripeCustomerId(customerId);

        if (user && subscription.trial_end) {
          const daysRemaining = Math.ceil(
            (subscription.trial_end * 1000 - Date.now()) /
              (1000 * 60 * 60 * 24),
          );
          await sendTrialEndingNotification(user.email, daysRemaining);
        }

        // Log the event
        const referenceId =
          (subscription.metadata.referenceId as string) ?? null;
        if (referenceId) {
          await logBillingEvent(referenceId, "trial_ending", {
            subscriptionId: subscription.id,
            trialEnd: subscription.trial_end,
          });
        }
        break;
      }

      case "customer.updated": {
        const customer = event.data.object as Stripe.Customer;
        console.log(`[Stripe Webhook] Customer updated: ${customer.id}`);
        break;
      }

      case "checkout.session.completed": {
        const session = event.data.object as Stripe.Checkout.Session;
        console.log(`[Stripe Webhook] Checkout completed: ${session.id}`);
        break;
      }

      default:
        console.log(`[Stripe Webhook] Unhandled event type: ${event.type}`);
    }
  } catch (error) {
    console.error(
      `[Stripe Webhook] Error handling event ${event.type}:`,
      error,
    );
    // Don't throw - let webhook succeed to avoid retries for non-critical errors
  }
}
