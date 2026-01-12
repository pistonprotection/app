import { createFileRoute } from "@tanstack/react-router"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { CreditCard, Download, Zap, Shield, Server, ArrowUpRight } from "lucide-react"

export const Route = createFileRoute("/dashboard/billing")({ component: BillingPage })

function BillingPage() {
  const currentPlan = { name: "Enterprise", price: 499, billingCycle: "monthly", renewalDate: "Feb 15, 2025" }
  const usage = { bandwidth: { used: 8.2, limit: 10, unit: "TB" }, requests: { used: 158, limit: 200, unit: "M" }, backends: { used: 12, limit: 25, unit: "" } }
  const invoices = [
    { id: "INV-2025-001", date: "Jan 15, 2025", amount: 499, status: "paid" },
    { id: "INV-2024-012", date: "Dec 15, 2024", amount: 499, status: "paid" },
    { id: "INV-2024-011", date: "Nov 15, 2024", amount: 499, status: "paid" },
    { id: "INV-2024-010", date: "Oct 15, 2024", amount: 399, status: "paid" },
  ]
  const plans = [
    { name: "Starter", price: 49, features: ["1 TB Bandwidth", "10M Requests", "5 Backends", "Email Support"] },
    { name: "Professional", price: 199, features: ["5 TB Bandwidth", "100M Requests", "15 Backends", "Priority Support", "Custom Filters"], popular: false },
    { name: "Enterprise", price: 499, features: ["10 TB Bandwidth", "200M Requests", "25 Backends", "24/7 Support", "Custom Filters", "Dedicated IP", "SLA 99.99%"], current: true },
  ]
  return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold tracking-tight">Billing</h1><p className="text-muted-foreground">Manage your subscription and billing information.</p></div>
      <div className="grid gap-4 md:grid-cols-3">
        <Card><CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2"><CardTitle className="text-sm font-medium">Current Plan</CardTitle><Shield className="h-4 w-4 text-muted-foreground" /></CardHeader><CardContent><div className="text-2xl font-bold">{currentPlan.name}</div><p className="text-xs text-muted-foreground">${currentPlan.price}/{currentPlan.billingCycle}</p></CardContent></Card>
        <Card><CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2"><CardTitle className="text-sm font-medium">Next Billing</CardTitle><CreditCard className="h-4 w-4 text-muted-foreground" /></CardHeader><CardContent><div className="text-2xl font-bold">${currentPlan.price}</div><p className="text-xs text-muted-foreground">{currentPlan.renewalDate}</p></CardContent></Card>
        <Card><CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2"><CardTitle className="text-sm font-medium">Payment Method</CardTitle><CreditCard className="h-4 w-4 text-muted-foreground" /></CardHeader><CardContent><div className="text-2xl font-bold">**** 4242</div><p className="text-xs text-muted-foreground">Visa - Expires 12/26</p></CardContent></Card>
      </div>
      <Card>
        <CardHeader><CardTitle>Usage This Period</CardTitle><CardDescription>Your resource consumption for the current billing cycle.</CardDescription></CardHeader>
        <CardContent className="space-y-6">
          <div className="space-y-2"><div className="flex items-center justify-between"><div className="flex items-center gap-2"><Zap className="h-4 w-4 text-muted-foreground" /><span className="text-sm font-medium">Bandwidth</span></div><span className="text-sm text-muted-foreground">{usage.bandwidth.used} / {usage.bandwidth.limit} {usage.bandwidth.unit}</span></div><Progress value={(usage.bandwidth.used / usage.bandwidth.limit) * 100} className="h-2" /></div>
          <div className="space-y-2"><div className="flex items-center justify-between"><div className="flex items-center gap-2"><Zap className="h-4 w-4 text-muted-foreground" /><span className="text-sm font-medium">Requests</span></div><span className="text-sm text-muted-foreground">{usage.requests.used} / {usage.requests.limit} {usage.requests.unit}</span></div><Progress value={(usage.requests.used / usage.requests.limit) * 100} className="h-2" /></div>
          <div className="space-y-2"><div className="flex items-center justify-between"><div className="flex items-center gap-2"><Server className="h-4 w-4 text-muted-foreground" /><span className="text-sm font-medium">Protected Backends</span></div><span className="text-sm text-muted-foreground">{usage.backends.used} / {usage.backends.limit}</span></div><Progress value={(usage.backends.used / usage.backends.limit) * 100} className="h-2" /></div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle>Available Plans</CardTitle><CardDescription>Upgrade or downgrade your subscription.</CardDescription></CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            {plans.map((p, i) => (
              <Card key={i} className={p.current ? "border-primary" : ""}>
                <CardHeader>
                  <div className="flex items-center justify-between"><CardTitle>{p.name}</CardTitle>{p.current && <Badge>Current</Badge>}</div>
                  <CardDescription><span className="text-3xl font-bold">${p.price}</span><span className="text-muted-foreground">/month</span></CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2 text-sm">{p.features.map((f, j) => (<li key={j} className="flex items-center gap-2"><ArrowUpRight className="h-4 w-4 text-green-500" />{f}</li>))}</ul>
                  <Button className="w-full mt-4" variant={p.current ? "outline" : "default"} disabled={p.current}>{p.current ? "Current Plan" : "Upgrade"}</Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle>Billing History</CardTitle><CardDescription>View and download past invoices.</CardDescription></CardHeader>
        <CardContent>
          <Table>
            <TableHeader><TableRow><TableHead>Invoice</TableHead><TableHead>Date</TableHead><TableHead>Amount</TableHead><TableHead>Status</TableHead><TableHead className="text-right">Actions</TableHead></TableRow></TableHeader>
            <TableBody>
              {invoices.map(inv => (
                <TableRow key={inv.id}>
                  <TableCell className="font-medium">{inv.id}</TableCell>
                  <TableCell>{inv.date}</TableCell>
                  <TableCell>${inv.amount}</TableCell>
                  <TableCell><Badge variant="secondary" className="bg-green-500/10 text-green-500">Paid</Badge></TableCell>
                  <TableCell className="text-right"><Button variant="ghost" size="sm"><Download className="mr-2 h-4 w-4" />PDF</Button></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
