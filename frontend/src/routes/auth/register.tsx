import { createFileRoute, Link } from "@tanstack/react-router"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Checkbox } from "@/components/ui/checkbox"
import { Shield } from "lucide-react"

export const Route = createFileRoute("/auth/register")({ component: RegisterPage })

function RegisterPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4"><div className="rounded-full bg-primary/10 p-3"><Shield className="h-8 w-8 text-primary" /></div></div>
          <CardTitle className="text-2xl">Create an account</CardTitle>
          <CardDescription>Start protecting your infrastructure today</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4"><div className="grid gap-2"><Label htmlFor="firstName">First Name</Label><Input id="firstName" placeholder="John" /></div><div className="grid gap-2"><Label htmlFor="lastName">Last Name</Label><Input id="lastName" placeholder="Doe" /></div></div>
          <div className="grid gap-2"><Label htmlFor="company">Company Name</Label><Input id="company" placeholder="Acme Inc." /></div>
          <div className="grid gap-2"><Label htmlFor="email">Email</Label><Input id="email" type="email" placeholder="you@example.com" /></div>
          <div className="grid gap-2"><Label htmlFor="password">Password</Label><Input id="password" type="password" placeholder="********" /><p className="text-xs text-muted-foreground">Must be at least 8 characters with uppercase, lowercase, and number.</p></div>
          <div className="flex items-start space-x-2"><Checkbox id="terms" /><Label htmlFor="terms" className="text-sm font-normal leading-tight">I agree to the{" "}<Link to="/" className="text-primary hover:underline">Terms of Service</Link>{" "}and{" "}<Link to="/" className="text-primary hover:underline">Privacy Policy</Link></Label></div>
          <Button className="w-full">Create Account</Button>
          <div className="relative"><div className="absolute inset-0 flex items-center"><span className="w-full border-t" /></div><div className="relative flex justify-center text-xs uppercase"><span className="bg-background px-2 text-muted-foreground">Or continue with</span></div></div>
          <div className="grid grid-cols-2 gap-4"><Button variant="outline">GitHub</Button><Button variant="outline">Google</Button></div>
          <p className="text-center text-sm text-muted-foreground">Already have an account?{" "}<Link to="/auth/login" className="text-primary hover:underline">Sign in</Link></p>
        </CardContent>
      </Card>
    </div>
  )
}
