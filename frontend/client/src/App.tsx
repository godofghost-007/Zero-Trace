import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Redirect, Route, Switch } from "wouter";
import AuthGate from "./components/AuthGate";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import { AuthProvider } from "./lib/auth";
import { DemoProvider } from "./lib/zeroTraceDemo";
import { SelectedTargetProvider } from "./lib/selectedTarget";
import Admin from "./pages/Admin";
import Guard from "./pages/Guard";
import Intel from "./pages/Intel";
import Recon from "./pages/Recon";
import ZeroTrace from "./pages/ZeroTrace";
import DemoShell from "./components/DemoShell";

function Router() {
  return (
    <DemoShell>
      <Switch>
        <Route path="/" component={ZeroTrace} />
        <Route path="/recon" component={Recon} />
        <Route path="/intel" component={Intel} />
        <Route path="/guard" component={Guard} />
        <Route path="/admin" component={Admin} />
        <Route path="/settings"><Redirect to="/admin" /></Route>
        <Route path="/targets"><Redirect to="/admin" /></Route>
        <Route path="/database"><Redirect to="/admin" /></Route>
        <Route path="/architecture"><Redirect to="/admin" /></Route>
        <Route path="/404" component={NotFound} />
        <Route component={NotFound} />
      </Switch>
    </DemoShell>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider defaultTheme="light">
        <TooltipProvider>
          <Toaster />
          <AuthProvider>
            <AuthGate>
              <DemoProvider>
                <SelectedTargetProvider><Router /></SelectedTargetProvider>
              </DemoProvider>
            </AuthGate>
          </AuthProvider>
        </TooltipProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}
