import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import {
  AlertTriangle,
  Check,
  CreditCard,
  Download,
  ExternalLink,
  Loader2,
  Server,
  Shield,
  Zap,
} from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useOrganizationId } from "@/hooks/use-organization";
import { useTRPC } from "@/lib/trpc/client";

export const Route = createFileRoute("/dashboard/billing")({
  component: BillingPage,
});

// Plan pricing (monthly prices in cents - would come from Stripe in production)
const planPricing: Record<
  string,
  {
    monthly: number;
    annual: number;
    billingType?: "flat" | "usage" | "hybrid";
    bandwidthPricePerGb?: number;
    requestsPricePerMillion?: number;
  }
> = {
  free: { monthly: 0, annual: 0, billingType: "flat" },
  starter: { monthly: 2900, annual: 29000, billingType: "flat" }, // $29/mo, $290/yr
  professional: {
    monthly: 9900,
    annual: 99000,
    billingType: "hybrid",
    bandwidthPricePerGb: 5,
    requestsPricePerMillion: 50,
  }, // $99/mo, $990/yr + overage
  enterprise: { monthly: 29900, annual: 299000, billingType: "flat" }, // $299/mo, $2990/yr
  "pay-as-you-go": {
    monthly: 0,
    annual: 0,
    billingType: "usage",
    bandwidthPricePerGb: 8,
    requestsPricePerMillion: 100,
  },
};

// Plan features for display
const planFeatures: Record<string, string[]> = {
  free: [
    "1 protected backend",
    "5 filter rules",
    "1 GB bandwidth/month",
    "100K requests/month",
    "Community support",
  ],
  starter: [
    "5 protected backends",
    "25 filter rules",
    "100 GB bandwidth/month",
    "10M requests/month",
    "Email support",
    "14-day free trial",
  ],
  professional: [
    "15 protected backends",
    "100 filter rules",
    "1 TB included bandwidth",
    "100M included requests",
    "Overage: $0.05/GB, $0.50/1M req",
    "Priority support",
    "Advanced analytics",
    "14-day free trial",
  ],
  enterprise: [
    "Unlimited backends",
    "Unlimited filter rules",
    "Unlimited bandwidth",
    "Unlimited requests",
    "24/7 dedicated support",
    "Custom integrations",
    "SLA guarantee",
    "14-day free trial",
  ],
  "pay-as-you-go": [
    "10 protected backends",
    "50 filter rules",
    "Pay per GB: $0.08/GB",
    "Pay per request: $1.00/1M",
    "No monthly minimum",
    "Scale as needed",
  ],
};

function BillingPage() {
  const [cancelDialogOpen, setCancelDialogOpen] = useState(false);
  const [upgradePlanName, setUpgradePlanName] = useState<string | null>(null);

  const trpc = useTRPC();
  const queryClient = useQueryClient();
  const organizationId = useOrganizationId();

  // Get current subscription
  const { data: subscription, isLoading: subLoading } = useQuery(
    trpc.billing.getSubscription.queryOptions({ organizationId }),
  );

  // Get usage
  const { data: usage, isLoading: usageLoading } = useQuery(
    trpc.billing.getUsage.queryOptions({ organizationId }),
  );

  // Get available plans
  const { data: plans, isLoading: plansLoading } = useQuery(
    trpc.billing.getPlans.queryOptions(),
  );

  // Get invoices
  const { data: invoices, isLoading: invoicesLoading } = useQuery(
    trpc.billing.getInvoices.queryOptions({ organizationId, limit: 10 }),
  );

  // Get payment methods
  const { data: paymentMethods } = useQuery(
    trpc.billing.getPaymentMethods.queryOptions({ organizationId }),
  );

  // Create checkout session for upgrade
  const upgradeMutation = useMutation(
    trpc.billing.createCheckoutSession.mutationOptions({
      onSuccess: (data) => {
        if (data.url) {
          window.location.href = data.url;
        }
      },
      onError: (error) => {
        toast.error(`Failed to start upgrade: ${error.message}`);
      },
    }),
  );

  // Open customer portal
  const portalMutation = useMutation(
    trpc.billing.createPortalSession.mutationOptions({
      onSuccess: (data) => {
        if (data.url) {
          window.location.href = data.url;
        }
      },
      onError: (error) => {
        toast.error(`Failed to open billing portal: ${error.message}`);
      },
    }),
  );

  // Cancel subscription
  const cancelMutation = useMutation(
    trpc.billing.cancelSubscription.mutationOptions({
      onSuccess: () => {
        toast.success(
          "Subscription cancelled. You will have access until the end of the billing period.",
        );
        setCancelDialogOpen(false);
        queryClient.invalidateQueries({ queryKey: ["billing"] });
      },
      onError: (error) => {
        toast.error(`Failed to cancel subscription: ${error.message}`);
      },
    }),
  );

  // Resume subscription
  const resumeMutation = useMutation(
    trpc.billing.resumeSubscription.mutationOptions({
      onSuccess: () => {
        toast.success("Subscription reactivated successfully.");
        queryClient.invalidateQueries({ queryKey: ["billing"] });
      },
      onError: (error) => {
        toast.error(`Failed to reactivate subscription: ${error.message}`);
      },
    }),
  );

  // Open invoice in new tab (Stripe hosted URL)
  const viewInvoice = (hostedUrl: string | null) => {
    if (hostedUrl) {
      window.open(hostedUrl, "_blank");
    } else {
      toast.error("Invoice URL not available");
    }
  };

  // Download invoice PDF
  const downloadInvoice = (
    pdfUrl: string | null,
    invoiceNumber: string | null,
  ) => {
    if (pdfUrl) {
      const link = document.createElement("a");
      link.href = pdfUrl;
      link.download = `invoice-${invoiceNumber ?? "download"}.pdf`;
      link.target = "_blank";
      link.click();
    } else {
      toast.error("Invoice PDF not available");
    }
  };

  const isLoading = subLoading || usageLoading || plansLoading;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  // Match current plan by name
  const currentPlanName = subscription?.plan ?? "free";
  const currentPricing = planPricing[currentPlanName] ?? planPricing.free;
  const defaultPaymentMethod = paymentMethods?.find((pm) => pm.isDefault);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Billing</h1>
          <p className="text-muted-foreground">
            Manage your subscription and billing.
          </p>
        </div>
        <Button
          variant="outline"
          onClick={() => portalMutation.mutate({ organizationId })}
          disabled={portalMutation.isPending}
        >
          {portalMutation.isPending ? (
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          ) : (
            <ExternalLink className="mr-2 h-4 w-4" />
          )}
          Manage Billing
        </Button>
      </div>

      {/* Subscription Status Alert */}
      {subscription?.status === "past_due" && (
        <Card className="border-destructive">
          <CardContent className="flex items-center gap-4 py-4">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <div className="flex-1">
              <p className="font-medium text-destructive">Payment Past Due</p>
              <p className="text-sm text-muted-foreground">
                Your payment is overdue. Please update your payment method to
                avoid service interruption.
              </p>
            </div>
            <Button
              variant="destructive"
              onClick={() => portalMutation.mutate({ organizationId })}
            >
              Update Payment
            </Button>
          </CardContent>
        </Card>
      )}

      {subscription?.cancelAtPeriodEnd && (
        <Card className="border-yellow-500">
          <CardContent className="flex items-center gap-4 py-4">
            <AlertTriangle className="h-5 w-5 text-yellow-500" />
            <div className="flex-1">
              <p className="font-medium text-yellow-600">
                Subscription Cancelling
              </p>
              <p className="text-sm text-muted-foreground">
                Your subscription will end on{" "}
                {subscription.currentPeriodEnd
                  ? new Date(subscription.currentPeriodEnd).toLocaleDateString()
                  : "the end of the billing period"}
                .
              </p>
            </div>
            <Button
              variant="outline"
              onClick={() => resumeMutation.mutate({ organizationId })}
              disabled={resumeMutation.isPending}
            >
              {resumeMutation.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Reactivate
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Usage Warning Alert */}
      {usage?.warningStatus?.needsWarning && (
        <Card className="border-orange-500">
          <CardContent className="flex items-center gap-4 py-4">
            <AlertTriangle className="h-5 w-5 text-orange-500" />
            <div className="flex-1">
              <p className="font-medium text-orange-600">
                Approaching Usage Limit
              </p>
              <p className="text-sm text-muted-foreground">
                {usage.bandwidth.percentage >=
                  (usage.warningStatus.threshold ?? 80) && (
                  <span>
                    Bandwidth at {usage.bandwidth.percentage}% of limit.{" "}
                  </span>
                )}
                {usage.requests?.percentage &&
                  usage.requests.percentage >=
                    (usage.warningStatus.threshold ?? 80) && (
                    <span>
                      Requests at {usage.requests.percentage}% of limit.{" "}
                    </span>
                  )}
                {usage.warningStatus.billingType === "hybrid" && (
                  <span className="block mt-1">
                    Overage charges may apply after limits are exceeded.
                  </span>
                )}
                {usage.warningStatus.hardCapEnabled && (
                  <span className="block mt-1 text-red-500">
                    Service will be suspended when limits are reached.
                  </span>
                )}
              </p>
            </div>
            <Button
              variant="outline"
              onClick={() => {
                // Find a better plan to upgrade to
                const currentIndex = [
                  "free",
                  "starter",
                  "professional",
                  "enterprise",
                ].indexOf(currentPlanName);
                const nextPlan = [
                  "starter",
                  "professional",
                  "enterprise",
                  "enterprise",
                ][currentIndex];
                if (nextPlan && nextPlan !== currentPlanName) {
                  const plan = plans?.find((p) => p.name === nextPlan);
                  if (plan?.lookupKey) {
                    upgradeMutation.mutate({
                      organizationId,
                      priceId: plan.lookupKey,
                      annual: false,
                    });
                  }
                }
              }}
            >
              Upgrade Plan
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Overage Cost Warning */}
      {usage?.warningStatus?.estimatedOverageCost &&
        usage.warningStatus.estimatedOverageCost > 0 && (
          <Card className="border-red-500">
            <CardContent className="flex items-center gap-4 py-4">
              <Zap className="h-5 w-5 text-red-500" />
              <div className="flex-1">
                <p className="font-medium text-red-600">
                  Overage Charges Applied
                </p>
                <p className="text-sm text-muted-foreground">
                  Estimated overage cost this period:{" "}
                  <span className="font-semibold">
                    $
                    {(usage.warningStatus.estimatedOverageCost / 100).toFixed(
                      2,
                    )}
                  </span>
                </p>
              </div>
            </CardContent>
          </Card>
        )}

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Current Plan</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold capitalize">
              {currentPlanName}
            </div>
            <p className="text-xs text-muted-foreground">
              {currentPricing.monthly > 0 ? (
                <>${(currentPricing.monthly / 100).toFixed(2)}/month</>
              ) : (
                "Free tier"
              )}
              {subscription?.isTrialing && (
                <Badge variant="secondary" className="ml-2">
                  Trial
                </Badge>
              )}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Next Billing</CardTitle>
            <CreditCard className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              ${(currentPricing.monthly / 100).toFixed(2)}
            </div>
            <p className="text-xs text-muted-foreground">
              {subscription?.currentPeriodEnd
                ? new Date(subscription.currentPeriodEnd).toLocaleDateString()
                : "N/A"}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Payment Method
            </CardTitle>
            <CreditCard className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            {defaultPaymentMethod ? (
              <>
                <div className="text-2xl font-bold">
                  **** {defaultPaymentMethod.last4}
                </div>
                <p className="text-xs text-muted-foreground capitalize">
                  {defaultPaymentMethod.brand} - Expires{" "}
                  {defaultPaymentMethod.expMonth}/{defaultPaymentMethod.expYear}
                </p>
              </>
            ) : (
              <>
                <div className="text-2xl font-bold">None</div>
                <p className="text-xs text-muted-foreground">
                  No payment method on file
                </p>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Usage */}
      <Card>
        <CardHeader>
          <CardTitle>Usage This Period</CardTitle>
          <CardDescription>
            Your resource consumption for the current billing cycle.
            {usage?.lastUsageReset && (
              <span className="block text-xs mt-1">
                Last reset:{" "}
                {new Date(usage.lastUsageReset).toLocaleDateString()}
              </span>
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Zap className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm font-medium">Bandwidth</span>
              </div>
              <span className="text-sm text-muted-foreground">
                {usage?.bandwidth.usedFormatted ?? "0 B"} /{" "}
                {usage?.bandwidth.unlimited
                  ? "Unlimited"
                  : (usage?.bandwidth.limitFormatted ?? "1 GB")}
              </span>
            </div>
            <Progress
              value={usage?.bandwidth.percentage ?? 0}
              className="h-2"
            />
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Server className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm font-medium">Protected Backends</span>
              </div>
              <span className="text-sm text-muted-foreground">
                {usage?.backends.used ?? 0} /{" "}
                {usage?.backends.unlimited
                  ? "Unlimited"
                  : (usage?.backends.limit ?? 1)}
              </span>
            </div>
            <Progress
              value={
                usage?.backends.unlimited
                  ? 0
                  : ((usage?.backends.used ?? 0) /
                      (usage?.backends.limit ?? 1)) *
                    100
              }
              className="h-2"
            />
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm font-medium">Filter Rules</span>
              </div>
              <span className="text-sm text-muted-foreground">
                {usage?.filters.used ?? 0} /{" "}
                {usage?.filters.unlimited
                  ? "Unlimited"
                  : (usage?.filters.limit ?? 5)}
              </span>
            </div>
            <Progress
              value={
                usage?.filters.unlimited
                  ? 0
                  : ((usage?.filters.used ?? 0) / (usage?.filters.limit ?? 5)) *
                    100
              }
              className="h-2"
            />
          </div>
        </CardContent>
      </Card>

      {/* Plans */}
      <Card>
        <CardHeader>
          <CardTitle>Available Plans</CardTitle>
          <CardDescription>
            Upgrade or downgrade your subscription.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {plans?.map((plan) => {
              const isCurrent = plan.name === currentPlanName;
              const pricing = planPricing[plan.name] ?? planPricing.free;
              const features = planFeatures[plan.name] ?? [];
              const currentPlanPrice = currentPricing.monthly;

              return (
                <Card
                  key={plan.name}
                  className={
                    isCurrent ? "border-primary ring-2 ring-primary/20" : ""
                  }
                >
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle className="capitalize">{plan.name}</CardTitle>
                      {isCurrent && <Badge>Current</Badge>}
                    </div>
                    <CardDescription>
                      <span className="text-3xl font-bold">
                        {pricing.monthly === 0
                          ? "Free"
                          : `$${(pricing.monthly / 100).toFixed(0)}`}
                      </span>
                      {pricing.monthly > 0 && (
                        <span className="text-muted-foreground">/month</span>
                      )}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ul className="space-y-2 text-sm mb-4">
                      {features.map((feature, j) => (
                        <li key={j} className="flex items-center gap-2">
                          <Check className="h-4 w-4 text-green-500 flex-shrink-0" />
                          <span>{feature}</span>
                        </li>
                      ))}
                    </ul>
                    <div className="text-xs text-muted-foreground mb-4">
                      <div>Backends: {plan.limits.backendsFormatted}</div>
                      <div>Filters: {plan.limits.filtersFormatted}</div>
                      <div>Bandwidth: {plan.limits.bandwidthFormatted}</div>
                    </div>
                    {plan.name === "free" ? (
                      <Button className="w-full" variant="outline" disabled>
                        {isCurrent ? "Current Plan" : "Default"}
                      </Button>
                    ) : (
                      <Button
                        className="w-full"
                        variant={isCurrent ? "outline" : "default"}
                        disabled={
                          isCurrent ||
                          upgradeMutation.isPending ||
                          !plan.lookupKey
                        }
                        onClick={() => {
                          if (!isCurrent && plan.lookupKey) {
                            setUpgradePlanName(plan.name);
                            upgradeMutation.mutate({
                              organizationId,
                              priceId: plan.lookupKey,
                              annual: false,
                            });
                          }
                        }}
                      >
                        {upgradeMutation.isPending &&
                        upgradePlanName === plan.name ? (
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        ) : null}
                        {isCurrent
                          ? "Current Plan"
                          : currentPlanPrice < pricing.monthly
                            ? "Upgrade"
                            : "Switch"}
                      </Button>
                    )}
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Invoices */}
      <Card>
        <CardHeader>
          <CardTitle>Billing History</CardTitle>
          <CardDescription>View and download past invoices.</CardDescription>
        </CardHeader>
        <CardContent>
          {invoicesLoading ? (
            <div className="flex justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : invoices?.length === 0 ? (
            <p className="text-center py-8 text-muted-foreground">
              No invoices yet
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Invoice</TableHead>
                  <TableHead>Date</TableHead>
                  <TableHead>Amount</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {invoices?.map((invoice) => (
                  <TableRow key={invoice.id}>
                    <TableCell className="font-medium">
                      {invoice.number ?? invoice.id.slice(0, 12)}
                    </TableCell>
                    <TableCell>
                      {invoice.date
                        ? new Date(invoice.date).toLocaleDateString()
                        : "N/A"}
                    </TableCell>
                    <TableCell>
                      ${invoice.amount.toFixed(2)} {invoice.currency}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant="secondary"
                        className={
                          invoice.status === "paid"
                            ? "bg-green-500/10 text-green-500"
                            : invoice.status === "open"
                              ? "bg-yellow-500/10 text-yellow-500"
                              : "bg-red-500/10 text-red-500"
                        }
                      >
                        {invoice.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right space-x-2">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() =>
                          viewInvoice(invoice.hostedInvoiceUrl ?? null)
                        }
                      >
                        <ExternalLink className="mr-2 h-4 w-4" />
                        View
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() =>
                          downloadInvoice(
                            invoice.invoicePdf ?? null,
                            invoice.number ?? null,
                          )
                        }
                      >
                        <Download className="mr-2 h-4 w-4" />
                        PDF
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Cancel Subscription */}
      {subscription &&
        subscription.plan !== "free" &&
        !subscription.cancelAtPeriodEnd && (
          <Card>
            <CardHeader>
              <CardTitle>Cancel Subscription</CardTitle>
              <CardDescription>
                Cancel your subscription. You will retain access until the end
                of your billing period.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Button
                variant="destructive"
                onClick={() => setCancelDialogOpen(true)}
              >
                Cancel Subscription
              </Button>
            </CardContent>
          </Card>
        )}

      {/* Cancel Confirmation Dialog */}
      <Dialog open={cancelDialogOpen} onOpenChange={setCancelDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Cancel Subscription</DialogTitle>
            <DialogDescription>
              Are you sure you want to cancel your subscription? You will retain
              access to the{" "}
              <span className="capitalize font-medium">{currentPlanName}</span>{" "}
              plan until{" "}
              {subscription?.currentPeriodEnd
                ? new Date(subscription.currentPeriodEnd).toLocaleDateString()
                : "the end of the billing period"}
              .
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setCancelDialogOpen(false)}
            >
              Keep Subscription
            </Button>
            <Button
              variant="destructive"
              onClick={() => cancelMutation.mutate({ organizationId })}
              disabled={cancelMutation.isPending}
            >
              {cancelMutation.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Cancel Subscription
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
