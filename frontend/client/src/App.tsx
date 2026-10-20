import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Route, Switch } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import { DemoProvider } from "./lib/zeroTraceDemo";
import Architecture from "./pages/Architecture";
import Database from "./pages/Database";
import Guard from "./pages/Guard";
import Intel from "./pages/Intel";
import Recon from "./pages/Recon";
import Settings from "./pages/Settings";
import Targets from "./pages/Targets";
import DemoShell from "./components/DemoShell";

function Router() {
  return (
    <DemoShell>
      <Switch>
        <Route path="/" component={Architecture} />
        <Route path="/database" component={Database} />
        <Route path="/recon" component={Recon} />
        <Route path="/intel" component={Intel} />
        <Route path="/guard" component={Guard} />
        <Route path="/targets" component={Targets} />
        <Route path="/settings" component={Settings} />
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
          <DemoProvider><Router /></DemoProvider>
        </TooltipProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}
