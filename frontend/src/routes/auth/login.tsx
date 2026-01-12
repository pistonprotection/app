import { createFileRoute, Link } from "@tanstack/react-router"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Checkbox } from "@/components/ui/checkbox"
import { Shield } from "lucide-react"

export const Route = createFileRoute("/auth/login")({ component: LoginPage })

function LoginPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4"><div className="rounded-full bg-primary/10 p-3"><Shield className="h-8 w-8 text-primary" /></div></div>
          <CardTitle className="text-2xl">Welcome back</CardTitle>
          <CardDescription>Sign in to your PistonProtection account</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-2"><Label htmlFor="email">Email</Label><Input id="email" type="email" placeholder="you@example.com" /></div>
          <div className="grid gap-2"><Label htmlFor="password">Password</Label><Input id="password" type="password" placeholder="********" /></div>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2"><Checkbox id="remember" /><Label htmlFor="remember" className="text-sm font-normal">Remember me</Label></div>
            <Link to="/auth/forgot-password" className="text-sm text-primary hover:underline">Forgot password?</Link>
          </div>
          <Button className="w-full">Sign In</Button>
          <div className="relative"><div className="absolute inset-0 flex items-center"><span className="w-full border-t" /></div><div className="relative flex justify-center text-xs uppercase"><span className="bg-background px-2 text-muted-foreground">Or continue with</span></div></div>
          <div className="grid grid-cols-2 gap-4"><Button variant="outline">GitHub</Button><Button variant="outline">Google</Button></div>
          <p className="text-center text-sm text-muted-foreground">Don't have an account?{" "}<Link to="/auth/register" className="text-primary hover:underline">Sign up</Link></p>
        </CardContent>
      </Card>
    </div>
  )
}
