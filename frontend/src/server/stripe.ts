import Stripe from "stripe";
import { env } from "@/env";

export const stripeClient = new Stripe(env.STRIPE_SECRET_KEY, {
  apiVersion: "2025-05-28.basil",
});

// Handle Stripe webhook events
export async function handleStripeEvent(event: Stripe.Event) {
  switch (event.type) {
    case "customer.subscription.created":
      console.log("Subscription created:", event.data.object.id);
      break;

    case "customer.subscription.updated":
      console.log("Subscription updated:", event.data.object.id);
      break;

    case "customer.subscription.deleted":
      console.log("Subscription deleted:", event.data.object.id);
      break;

    case "invoice.payment_succeeded":
      console.log("Payment succeeded:", event.data.object.id);
      break;

    case "invoice.payment_failed":
      console.log("Payment failed:", event.data.object.id);
      // Could send a notification email here
      break;

    case "customer.subscription.trial_will_end":
      console.log("Trial will end:", event.data.object.id);
      // Could send a reminder email here
      break;

    default:
      console.log(`Unhandled event type: ${event.type}`);
  }
}
