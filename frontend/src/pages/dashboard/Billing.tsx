import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Check,
  CreditCard,
  Download,
  Zap,
  Server,
  Filter,
  Globe,
  AlertTriangle,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import {
  subscriptionQueryOptions,
  plansQueryOptions,
  useUpgradeSubscription,
  useCancelSubscription,
  type Plan,
} from "@/lib/api";
import { formatBytes, formatNumber, formatDate } from "@/lib/utils";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

// Mock data
const mockSubscription = {
  id: "sub_123",
  plan: "professional" as const,
  status: "active" as const,
  currentPeriodStart: "2024-01-01",
  currentPeriodEnd: "2024-02-01",
  cancelAtPeriodEnd: false,
  usage: {
    requests: 25847293,
    requestsLimit: 50000000,
    bandwidth: 1024 * 1024 * 1024 * 45.7,
    bandwidthLimit: 1024 * 1024 * 1024 * 100,
    backends: 5,
    backendsLimit: 10,
    rules: 23,
    rulesLimit: 50,
  },
};

const mockPlans: Plan[] = [
  {
    id: "free",
    name: "Free",
    price: 0,
    interval: "monthly",
    features: [
      "1 Backend",
      "5 Filter Rules",
      "1M Requests/month",
      "10GB Bandwidth",
      "Community Support",
    ],
    limits: {
      requests: 1000000,
      bandwidth: 1024 * 1024 * 1024 * 10,
      backends: 1,
      rules: 5,
    },
  },
  {
    id: "starter",
    name: "Starter",
    price: 29,
    interval: "monthly",
    features: [
      "3 Backends",
      "15 Filter Rules",
      "10M Requests/month",
      "50GB Bandwidth",
      "Email Support",
      "Basic Analytics",
    ],
    limits: {
      requests: 10000000,
      bandwidth: 1024 * 1024 * 1024 * 50,
      backends: 3,
      rules: 15,
    },
  },
  {
    id: "professional",
    name: "Professional",
    price: 99,
    interval: "monthly",
    features: [
      "10 Backends",
      "50 Filter Rules",
      "50M Requests/month",
      "100GB Bandwidth",
      "Priority Support",
      "Advanced Analytics",
      "Custom SSL",
      "API Access",
    ],
    limits: {
      requests: 50000000,
      bandwidth: 1024 * 1024 * 1024 * 100,
      backends: 10,
      rules: 50,
    },
  },
  {
    id: "enterprise",
    name: "Enterprise",
    price: 499,
    interval: "monthly",
    features: [
      "Unlimited Backends",
      "Unlimited Filter Rules",
      "Unlimited Requests",
      "Unlimited Bandwidth",
      "24/7 Phone Support",
      "Enterprise Analytics",
      "Custom SSL",
      "Full API Access",
      "SLA Guarantee",
      "Dedicated Account Manager",
    ],
    limits: {
      requests: -1,
      bandwidth: -1,
      backends: -1,
      rules: -1,
    },
  },
];

const mockInvoices = [
  {
    id: "inv_001",
    date: "2024-01-01",
    amount: 99,
    status: "paid",
    description: "Professional Plan - January 2024",
  },
  {
    id: "inv_002",
    date: "2023-12-01",
    amount: 99,
    status: "paid",
    description: "Professional Plan - December 2023",
  },
  {
    id: "inv_003",
    date: "2023-11-01",
    amount: 99,
    status: "paid",
    description: "Professional Plan - November 2023",
  },
];

export function Billing() {
  const [selectedPlan, setSelectedPlan] = useState<Plan | null>(null);
  const [isUpgradeDialogOpen, setIsUpgradeDialogOpen] = useState(false);
  const [isCancelDialogOpen, setIsCancelDialogOpen] = useState(false);

  const { data: subscription, isLoading: subscriptionLoading } = useQuery({
    ...subscriptionQueryOptions(),
    placeholderData: mockSubscription,
  });

  const { data: plans, isLoading: plansLoading } = useQuery({
    ...plansQueryOptions(),
    placeholderData: mockPlans,
  });

  const upgradeSubscription = useUpgradeSubscription();
  const cancelSubscription = useCancelSubscription();

  const currentPlan = plans?.find((p) => p.id === subscription?.plan);

  const handleUpgrade = async () => {
    if (!selectedPlan) return;
    try {
      await upgradeSubscription.mutateAsync(selectedPlan.id);
      toast.success(`Successfully upgraded to ${selectedPlan.name} plan`);
      setIsUpgradeDialogOpen(false);
      setSelectedPlan(null);
    } catch {
      toast.error("Failed to upgrade subscription");
    }
  };

  const handleCancel = async () => {
    try {
      await cancelSubscription.mutateAsync();
      toast.success("Subscription will be canceled at the end of the billing period");
      setIsCancelDialogOpen(false);
    } catch {
      toast.error("Failed to cancel subscription");
    }
  };

  const getUsagePercentage = (used: number, limit: number) => {
    if (limit <= 0) return 0;
    return (used / limit) * 100;
  };

  const getUsageColor = (percentage: number) => {
    if (percentage >= 90) return "text-destructive";
    if (percentage >= 75) return "text-yellow-500";
    return "text-foreground";
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Billing</h1>
        <p className="text-muted-foreground">
          Manage your subscription and billing information
        </p>
      </div>

      {/* Current Plan Card */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Current Plan</CardTitle>
              <CardDescription>
                Your subscription and usage details
              </CardDescription>
            </div>
            {subscriptionLoading ? (
              <Skeleton className="h-8 w-24" />
            ) : (
              <div className="flex items-center gap-2">
                <Badge variant="nova" className="text-lg px-4 py-1">
                  {currentPlan?.name || "Free"}
                </Badge>
                <Badge
                  variant={
                    subscription?.status === "active" ? "success" : "destructive"
                  }
                >
                  {subscription?.status}
                </Badge>
              </div>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {subscriptionLoading ? (
            <div className="space-y-4">
              <Skeleton className="h-8 w-full" />
              <Skeleton className="h-8 w-full" />
              <Skeleton className="h-8 w-full" />
            </div>
          ) : (
            <div className="grid gap-6 md:grid-cols-2">
              {/* Usage Stats */}
              <div className="space-y-4">
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2">
                      <Globe className="h-4 w-4 text-muted-foreground" />
                      <span>Requests</span>
                    </div>
                    <span
                      className={cn(
                        getUsageColor(
                          getUsagePercentage(
                            subscription?.usage.requests || 0,
                            subscription?.usage.requestsLimit || 1
                          )
                        )
                      )}
                    >
                      {formatNumber(subscription?.usage.requests || 0)} /{" "}
                      {formatNumber(subscription?.usage.requestsLimit || 0)}
                    </span>
                  </div>
                  <Progress
                    value={getUsagePercentage(
                      subscription?.usage.requests || 0,
                      subscription?.usage.requestsLimit || 1
                    )}
                  />
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2">
                      <Zap className="h-4 w-4 text-muted-foreground" />
                      <span>Bandwidth</span>
                    </div>
                    <span
                      className={cn(
                        getUsageColor(
                          getUsagePercentage(
                            subscription?.usage.bandwidth || 0,
                            subscription?.usage.bandwidthLimit || 1
                          )
                        )
                      )}
                    >
                      {formatBytes(subscription?.usage.bandwidth || 0)} /{" "}
                      {formatBytes(subscription?.usage.bandwidthLimit || 0)}
                    </span>
                  </div>
                  <Progress
                    value={getUsagePercentage(
                      subscription?.usage.bandwidth || 0,
                      subscription?.usage.bandwidthLimit || 1
                    )}
                  />
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2">
                      <Server className="h-4 w-4 text-muted-foreground" />
                      <span>Backends</span>
                    </div>
                    <span>
                      {subscription?.usage.backends || 0} /{" "}
                      {subscription?.usage.backendsLimit || 0}
                    </span>
                  </div>
                  <Progress
                    value={getUsagePercentage(
                      subscription?.usage.backends || 0,
                      subscription?.usage.backendsLimit || 1
                    )}
                  />
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2">
                      <Filter className="h-4 w-4 text-muted-foreground" />
                      <span>Filter Rules</span>
                    </div>
                    <span>
                      {subscription?.usage.rules || 0} /{" "}
                      {subscription?.usage.rulesLimit || 0}
                    </span>
                  </div>
                  <Progress
                    value={getUsagePercentage(
                      subscription?.usage.rules || 0,
                      subscription?.usage.rulesLimit || 1
                    )}
                  />
                </div>
              </div>

              {/* Billing Info */}
              <div className="space-y-4">
                <div className="rounded-lg border p-4">
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-sm text-muted-foreground">
                      Current Period
                    </span>
                    <span className="text-sm">
                      {formatDate(subscription?.currentPeriodStart || "")} -{" "}
                      {formatDate(subscription?.currentPeriodEnd || "")}
                    </span>
                  </div>
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-sm text-muted-foreground">
                      Next Invoice
                    </span>
                    <span className="text-sm font-medium">
                      ${currentPlan?.price || 0}/month
                    </span>
                  </div>
                  {subscription?.cancelAtPeriodEnd && (
                    <div className="flex items-center gap-2 p-2 rounded bg-destructive/10 text-destructive text-sm">
                      <AlertTriangle className="h-4 w-4" />
                      <span>
                        Cancels on{" "}
                        {formatDate(subscription.currentPeriodEnd)}
                      </span>
                    </div>
                  )}
                </div>

                <div className="flex gap-2">
                  <Button
                    className="flex-1"
                    onClick={() => setIsUpgradeDialogOpen(true)}
                    disabled={subscription?.plan === "enterprise"}
                  >
                    Upgrade Plan
                  </Button>
                  {subscription?.status === "active" &&
                    !subscription?.cancelAtPeriodEnd && (
                      <Button
                        variant="outline"
                        onClick={() => setIsCancelDialogOpen(true)}
                      >
                        Cancel
                      </Button>
                    )}
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Plans */}
      <div>
        <h2 className="text-2xl font-bold mb-4">Available Plans</h2>
        {plansLoading ? (
          <div className="grid gap-4 md:grid-cols-4">
            {[1, 2, 3, 4].map((i) => (
              <Skeleton key={i} className="h-[400px] w-full" />
            ))}
          </div>
        ) : (
          <div className="grid gap-4 md:grid-cols-4">
            {plans?.map((plan) => (
              <Card
                key={plan.id}
                className={cn(
                  "relative",
                  plan.id === subscription?.plan && "border-nova"
                )}
              >
                {plan.id === "professional" && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                    <Badge variant="nova">Most Popular</Badge>
                  </div>
                )}
                <CardHeader>
                  <CardTitle>{plan.name}</CardTitle>
                  <CardDescription>
                    <span className="text-3xl font-bold">${plan.price}</span>
                    <span className="text-muted-foreground">/month</span>
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2">
                    {plan.features.map((feature, index) => (
                      <li key={index} className="flex items-center gap-2 text-sm">
                        <Check className="h-4 w-4 text-green-500" />
                        {feature}
                      </li>
                    ))}
                  </ul>
                </CardContent>
                <CardFooter>
                  {plan.id === subscription?.plan ? (
                    <Button className="w-full" disabled>
                      Current Plan
                    </Button>
                  ) : (
                    <Button
                      className="w-full"
                      variant={plan.id === "professional" ? "default" : "outline"}
                      onClick={() => {
                        setSelectedPlan(plan);
                        setIsUpgradeDialogOpen(true);
                      }}
                    >
                      {plan.price > (currentPlan?.price || 0)
                        ? "Upgrade"
                        : "Downgrade"}
                    </Button>
                  )}
                </CardFooter>
              </Card>
            ))}
          </div>
        )}
      </div>

      {/* Payment Method */}
      <Card>
        <CardHeader>
          <CardTitle>Payment Method</CardTitle>
          <CardDescription>Manage your payment information</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-muted">
                <CreditCard className="h-6 w-6" />
              </div>
              <div>
                <p className="font-medium">Visa ending in 4242</p>
                <p className="text-sm text-muted-foreground">Expires 12/2025</p>
              </div>
            </div>
            <Button variant="outline">Update</Button>
          </div>
        </CardContent>
      </Card>

      {/* Billing History */}
      <Card>
        <CardHeader>
          <CardTitle>Billing History</CardTitle>
          <CardDescription>View and download past invoices</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Date</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Amount</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="w-[100px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {mockInvoices.map((invoice) => (
                <TableRow key={invoice.id}>
                  <TableCell>{formatDate(invoice.date)}</TableCell>
                  <TableCell>{invoice.description}</TableCell>
                  <TableCell>${invoice.amount.toFixed(2)}</TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        invoice.status === "paid" ? "success" : "secondary"
                      }
                    >
                      {invoice.status}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Button variant="ghost" size="sm">
                      <Download className="h-4 w-4 mr-2" />
                      PDF
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Upgrade Dialog */}
      <Dialog open={isUpgradeDialogOpen} onOpenChange={setIsUpgradeDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {selectedPlan &&
              selectedPlan.price > (currentPlan?.price || 0)
                ? "Upgrade"
                : "Change"}{" "}
              to {selectedPlan?.name}
            </DialogTitle>
            <DialogDescription>
              {selectedPlan &&
              selectedPlan.price > (currentPlan?.price || 0) ? (
                <>
                  You'll be charged{" "}
                  <span className="font-medium">
                    ${selectedPlan?.price}/month
                  </span>{" "}
                  starting today. Your new limits will be available immediately.
                </>
              ) : (
                <>
                  Your plan will be changed to {selectedPlan?.name} at the end
                  of your current billing period.
                </>
              )}
            </DialogDescription>
          </DialogHeader>
          {selectedPlan && (
            <div className="py-4">
              <h4 className="font-medium mb-2">New Plan Features:</h4>
              <ul className="space-y-2">
                {selectedPlan.features.slice(0, 5).map((feature, index) => (
                  <li key={index} className="flex items-center gap-2 text-sm">
                    <Check className="h-4 w-4 text-green-500" />
                    {feature}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setIsUpgradeDialogOpen(false)}
            >
              Cancel
            </Button>
            <Button
              onClick={handleUpgrade}
              disabled={upgradeSubscription.isPending}
            >
              {upgradeSubscription.isPending
                ? "Processing..."
                : `Confirm ${
                    selectedPlan &&
                    selectedPlan.price > (currentPlan?.price || 0)
                      ? "Upgrade"
                      : "Change"
                  }`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Cancel Dialog */}
      <AlertDialog open={isCancelDialogOpen} onOpenChange={setIsCancelDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Cancel Subscription</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to cancel your subscription? You'll lose
              access to premium features at the end of your current billing
              period on {formatDate(subscription?.currentPeriodEnd || "")}.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Keep Subscription</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleCancel}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {cancelSubscription.isPending
                ? "Canceling..."
                : "Cancel Subscription"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
