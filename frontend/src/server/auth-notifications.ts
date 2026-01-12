import { Resend } from "resend";
import { env } from "@/env";

const resend = new Resend(env.RESEND_API_KEY);
const baseUrl = env.PUBLIC_APP_URL;
const siteName = "PistonProtection";
const fromEmail = "noreply@pistonprotection.com";

interface User {
  id: string;
  email: string;
  name: string;
}

interface Organization {
  id: string;
  name: string;
  slug: string;
}

interface Inviter {
  email: string;
  name: string;
}

export const authNotifications = {
  async sendPasswordReset({ user, url }: { user: User; url: string }) {
    await resend.emails.send({
      from: `${siteName} <${fromEmail}>`,
      to: user.email,
      subject: `Reset your ${siteName} password`,
      html: `
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
          <h1 style="color: #1a1a1a;">Reset Your Password</h1>
          <p>Hi ${user.name || "there"},</p>
          <p>We received a request to reset your password. Click the button below to create a new password:</p>
          <p style="margin: 24px 0;">
            <a href="${url}" style="background-color: #0066cc; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
              Reset Password
            </a>
          </p>
          <p style="color: #666;">If you didn't request this, you can safely ignore this email. The link will expire in 1 hour.</p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
          <p style="color: #999; font-size: 12px;">${siteName} - Enterprise DDoS Protection</p>
        </div>
      `,
    });
  },

  async sendEmailVerification({ user, url }: { user: User; url: string }) {
    await resend.emails.send({
      from: `${siteName} <${fromEmail}>`,
      to: user.email,
      subject: `Verify your ${siteName} email`,
      html: `
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
          <h1 style="color: #1a1a1a;">Verify Your Email</h1>
          <p>Hi ${user.name || "there"},</p>
          <p>Welcome to ${siteName}! Please verify your email address to complete your registration:</p>
          <p style="margin: 24px 0;">
            <a href="${url}" style="background-color: #0066cc; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
              Verify Email
            </a>
          </p>
          <p style="color: #666;">If you didn't create an account, you can safely ignore this email.</p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
          <p style="color: #999; font-size: 12px;">${siteName} - Enterprise DDoS Protection</p>
        </div>
      `,
    });
  },

  async sendChangeEmailVerification({
    user,
    url,
  }: {
    user: User;
    url: string;
  }) {
    await resend.emails.send({
      from: `${siteName} <${fromEmail}>`,
      to: user.email,
      subject: `Verify your new email address`,
      html: `
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
          <h1 style="color: #1a1a1a;">Verify Your New Email</h1>
          <p>Hi ${user.name || "there"},</p>
          <p>You requested to change your email address. Click the button below to verify your new email:</p>
          <p style="margin: 24px 0;">
            <a href="${url}" style="background-color: #0066cc; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
              Verify New Email
            </a>
          </p>
          <p style="color: #666;">If you didn't request this change, please contact support immediately.</p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
          <p style="color: #999; font-size: 12px;">${siteName} - Enterprise DDoS Protection</p>
        </div>
      `,
    });
  },

  async sendDeleteAccountVerification({
    user,
    url,
  }: {
    user: User;
    url: string;
  }) {
    await resend.emails.send({
      from: `${siteName} <${fromEmail}>`,
      to: user.email,
      subject: `Confirm account deletion`,
      html: `
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
          <h1 style="color: #dc2626;">Confirm Account Deletion</h1>
          <p>Hi ${user.name || "there"},</p>
          <p>You requested to delete your ${siteName} account. This action is permanent and cannot be undone.</p>
          <p>If you're sure, click the button below to confirm:</p>
          <p style="margin: 24px 0;">
            <a href="${url}" style="background-color: #dc2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
              Delete My Account
            </a>
          </p>
          <p style="color: #666;">If you didn't request this, please secure your account immediately.</p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
          <p style="color: #999; font-size: 12px;">${siteName} - Enterprise DDoS Protection</p>
        </div>
      `,
    });
  },

  async sendTwoFactorOTP({ user, otp }: { user: User; otp: string }) {
    await resend.emails.send({
      from: `${siteName} <${fromEmail}>`,
      to: user.email,
      subject: `Your ${siteName} verification code`,
      html: `
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
          <h1 style="color: #1a1a1a;">Verification Code</h1>
          <p>Hi ${user.name || "there"},</p>
          <p>Your two-factor authentication code is:</p>
          <p style="font-size: 32px; font-weight: bold; letter-spacing: 8px; text-align: center; margin: 24px 0; color: #0066cc;">
            ${otp}
          </p>
          <p style="color: #666;">This code will expire in 5 minutes. Do not share this code with anyone.</p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
          <p style="color: #999; font-size: 12px;">${siteName} - Enterprise DDoS Protection</p>
        </div>
      `,
    });
  },

  async sendEmailOTP({
    email,
    otp,
    type,
  }: {
    email: string;
    otp: string;
    type: string;
  }) {
    const subject =
      type === "sign-in"
        ? `Your sign-in code for ${siteName}`
        : `Your verification code for ${siteName}`;

    await resend.emails.send({
      from: `${siteName} <${fromEmail}>`,
      to: email,
      subject,
      html: `
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
          <h1 style="color: #1a1a1a;">Your Code</h1>
          <p>Use this code to ${type === "sign-in" ? "sign in" : "verify your email"}:</p>
          <p style="font-size: 32px; font-weight: bold; letter-spacing: 8px; text-align: center; margin: 24px 0; color: #0066cc;">
            ${otp}
          </p>
          <p style="color: #666;">This code will expire in 10 minutes.</p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
          <p style="color: #999; font-size: 12px;">${siteName} - Enterprise DDoS Protection</p>
        </div>
      `,
    });
  },

  async sendOrganizationInvitation({
    id,
    role,
    email,
    inviter,
    organization,
  }: {
    id: string;
    role: string | null;
    email: string;
    inviter: Inviter;
    organization: Organization;
  }) {
    const inviteUrl = `${baseUrl}/auth/accept-invitation?id=${id}`;

    await resend.emails.send({
      from: `${siteName} <${fromEmail}>`,
      to: email,
      subject: `You've been invited to join ${organization.name} on ${siteName}`,
      html: `
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
          <h1 style="color: #1a1a1a;">Organization Invitation</h1>
          <p>Hi there,</p>
          <p><strong>${inviter.name || inviter.email}</strong> has invited you to join <strong>${organization.name}</strong> on ${siteName} as a <strong>${role || "member"}</strong>.</p>
          <p style="margin: 24px 0;">
            <a href="${inviteUrl}" style="background-color: #0066cc; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
              Accept Invitation
            </a>
          </p>
          <p style="color: #666;">This invitation will expire in 7 days.</p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
          <p style="color: #999; font-size: 12px;">${siteName} - Enterprise DDoS Protection</p>
        </div>
      `,
    });
  },

  async sendWelcomeEmail(email: string, planName: string) {
    await resend.emails.send({
      from: `${siteName} <${fromEmail}>`,
      to: email,
      subject: `Welcome to ${siteName} ${planName}!`,
      html: `
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
          <h1 style="color: #1a1a1a;">Welcome to ${siteName}!</h1>
          <p>Thank you for subscribing to our <strong>${planName}</strong> plan!</p>
          <p>Your DDoS protection is now active. Here's what you can do next:</p>
          <ul style="color: #444; line-height: 1.8;">
            <li>Add your backend servers to protect</li>
            <li>Configure custom filter rules</li>
            <li>Set up health checks and monitoring</li>
            <li>Invite team members to your organization</li>
          </ul>
          <p style="margin: 24px 0;">
            <a href="${baseUrl}/dashboard" style="background-color: #0066cc; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
              Go to Dashboard
            </a>
          </p>
          <p style="color: #666;">If you have any questions, our support team is here to help.</p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
          <p style="color: #999; font-size: 12px;">${siteName} - Enterprise DDoS Protection</p>
        </div>
      `,
    });
  },

  async sendCancellationEmail(email: string) {
    await resend.emails.send({
      from: `${siteName} <${fromEmail}>`,
      to: email,
      subject: `Your ${siteName} subscription has been cancelled`,
      html: `
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
          <h1 style="color: #1a1a1a;">Subscription Cancelled</h1>
          <p>Your ${siteName} subscription has been cancelled.</p>
          <p>You'll continue to have access to your current plan until the end of your billing period. After that, your account will be downgraded to the free tier.</p>
          <p>We're sorry to see you go. If you have any feedback about why you're leaving, we'd love to hear it.</p>
          <p style="margin: 24px 0;">
            <a href="${baseUrl}/dashboard/billing" style="background-color: #0066cc; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
              Reactivate Subscription
            </a>
          </p>
          <hr style="border: none; border-top: 1px solid #eee; margin: 24px 0;">
          <p style="color: #999; font-size: 12px;">${siteName} - Enterprise DDoS Protection</p>
        </div>
      `,
    });
  },
};
