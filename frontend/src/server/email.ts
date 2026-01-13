import { Resend } from "resend";
import { env } from "@/env";

const resend = new Resend(env.RESEND_API_KEY);

/**
 * Send an email using Resend
 */
export async function sendEmail(
  from: string,
  to: string,
  replyTo: string,
  subject: string,
  html: string,
): Promise<void> {
  await resend.emails.send({
    from,
    to,
    replyTo,
    subject,
    html,
  });
}
