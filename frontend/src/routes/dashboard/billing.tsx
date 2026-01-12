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
import { useTRPC } from "@/lib/trpc/client";

export const Route = createFileRoute("/dashboard/billing")({
  component: BillingPage,
});

function BillingPage() {
  const [cancelDialogOpen, setCancelDialogOpen] = useState(false);
  const [upgradePlanId, setUpgradePlanId] = useState<string | null>(null);

  const trpc = useTRPC();
  const queryClient = useQueryClient();

  // Get current subscription
  const { data: subscription, isLoading: subLoading } = useQuery(
    trpc.billing.getSubscription.queryOptions(),
  );

  // Get usage
  const { data: usage, isLoading: usageLoading } = useQuery(
    trpc.billing.getUsage.queryOptions(),
  );

  // Get available plans
  const { data: plans, isLoading: plansLoading } = useQuery(
    trpc.billing.getPlans.queryOptions(),
  );

  // Get invoices
  const { data: invoices, isLoading: invoicesLoading } = useQuery(
    trpc.billing.getInvoices.queryOptions({ limit: 10 }),
  );

  // Get payment methods
  const { data: paymentMethods } = useQuery(
    trpc.billing.getPaymentMethods.queryOptions(),
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

  // Download invoice
  const downloadInvoice = async (invoiceId: string) => {
    try {
      const response = await fetch(
        `/api/billing/invoices/${invoiceId}/download`,
      );
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `invoice-${invoiceId}.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch {
      toast.error("Failed to download invoice");
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

  const currentPlan = plans?.find((p) => p.id === subscription?.planId);
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
          onClick={() => portalMutation.mutate()}
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
              onClick={() => portalMutation.mutate()}
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
              onClick={() =>
                trpc.billing.reactivateSubscription
                  .mutate()
                  .then(() => {
                    toast.success("Subscription reactivated");
                    queryClient.invalidateQueries({ queryKey: ["billing"] });
                  })
                  .catch((e) => toast.error(e.message))
              }
            >
              Reactivate
            </Button>
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
            <div className="text-2xl font-bold">
              {currentPlan?.name ?? "Free"}
            </div>
            <p className="text-xs text-muted-foreground">
              {currentPlan ? (
                <>
                  ${(currentPlan.price / 100).toFixed(2)}/{currentPlan.interval}
                </>
              ) : (
                "No active subscription"
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
              {currentPlan ? `$${(currentPlan.price / 100).toFixed(2)}` : "$0"}
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
                <p className="text-xs text-muted-foreground">
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
                {formatBytes(usage?.bandwidthUsed ?? 0)} /{" "}
                {usage?.bandwidthLimit
                  ? formatBytes(usage.bandwidthLimit)
                  : "Unlimited"}
              </span>
            </div>
            <Progress
              value={
                usage?.bandwidthLimit
                  ? ((usage?.bandwidthUsed ?? 0) / usage.bandwidthLimit) * 100
                  : 0
              }
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
                {usage?.backendsUsed ?? 0} /{" "}
                {usage?.backendsLimit ?? "Unlimited"}
              </span>
            </div>
            <Progress
              value={
                usage?.backendsLimit
                  ? ((usage?.backendsUsed ?? 0) / usage.backendsLimit) * 100
                  : 0
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
                {usage?.filtersUsed ?? 0} / {usage?.filtersLimit ?? "Unlimited"}
              </span>
            </div>
            <Progress
              value={
                usage?.filtersLimit
                  ? ((usage?.filtersUsed ?? 0) / usage.filtersLimit) * 100
                  : 0
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
          <div className="grid gap-4 md:grid-cols-3">
            {plans?.map((plan) => {
              const isCurrent = plan.id === subscription?.planId;
              return (
                <Card
                  key={plan.id}
                  className={isCurrent ? "border-primary" : ""}
                >
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <CardTitle>{plan.name}</CardTitle>
                      {isCurrent && <Badge>Current</Badge>}
                    </div>
                    <CardDescription>
                      <span className="text-3xl font-bold">
                        ${(plan.price / 100).toFixed(0)}
                      </span>
                      /{plan.interval}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ul className="space-y-2 text-sm">
                      {plan.features?.map((feature, j) => (
                        <li key={j} className="flex items-center gap-2">
                          <Check className="h-4 w-4 text-green-500" />
                          {feature}
                        </li>
                      ))}
                    </ul>
                    <Button
                      className="w-full mt-4"
                      variant={isCurrent ? "outline" : "default"}
                      disabled={isCurrent || upgradeMutation.isPending}
                      onClick={() => {
                        if (!isCurrent) {
                          setUpgradePlanId(plan.id);
                          upgradeMutation.mutate({ planId: plan.id });
                        }
                      }}
                    >
                      {upgradeMutation.isPending &&
                      upgradePlanId === plan.id ? (
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      ) : null}
                      {isCurrent
                        ? "Current Plan"
                        : (currentPlan?.price ?? 0) < plan.price
                          ? "Upgrade"
                          : "Downgrade"}
                    </Button>
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
                      {new Date(invoice.createdAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell>${(invoice.amount / 100).toFixed(2)}</TableCell>
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
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => downloadInvoice(invoice.id)}
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
      {subscription && !subscription.cancelAtPeriodEnd && (
        <Card>
          <CardHeader>
            <CardTitle>Cancel Subscription</CardTitle>
            <CardDescription>
              Cancel your subscription. You will retain access until the end of
              your billing period.
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
              access to {currentPlan?.name ?? "your plan"} until{" "}
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
              onClick={() => cancelMutation.mutate()}
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

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${Number.parseFloat((bytes / k ** i).toFixed(2))} ${sizes[i]}`;
}
