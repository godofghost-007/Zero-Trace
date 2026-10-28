import type { ReactNode } from "react";
import { ArrowRight, Crosshair, FileText, LogOut, Radar, RefreshCcw, Settings2, Shield, ShieldCheck, UserRound } from "lucide-react";
import { Link, useLocation } from "wouter";
import { useAuth } from "@/lib/auth";
import { useZeroTraceDemo } from "@/lib/zeroTraceDemo";

const nav = [
  { href: "/", label: "ZeroTrace", icon: Crosshair, code: "00" },
  { href: "/recon", label: "Trace Recon", icon: Radar, code: "01" },
  { href: "/intel", label: "Intel Guard", icon: FileText, code: "02" },
  { href: "/guard", label: "Trace Guard", icon: Shield, code: "03" },
  { href: "/admin", label: "Admin", icon: Settings2, code: "04" },
];

export default function DemoShell({ children }: { children: ReactNode }) {
  const [path] = useLocation();
  const { user, logout } = useAuth();
  const { stage, runAll, reset, refresh, isProcessing, isConnected, connectionError, backend, readiness } = useZeroTraceDemo();
  const currentStep = readiness.score === null ? "COVERAGE PENDING" : `READINESS ${readiness.score.toFixed(0)}`;
  const connectionLabel = isConnected ? `${backend.database.toUpperCase()} API CONNECTED` : backend.database === "connecting" ? "CONNECTING TO API" : "API OFFLINE";
  const isDemoPage = path === "/guard";
  const canOperate = user?.role === "operator" || user?.role === "admin";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Link href="/" className="brand-lockup"><span className="brand-mark"><ShieldCheck size={20} strokeWidth={2.2} /></span><span><strong>ZeroTrace</strong><small>FIELD SYSTEM / 02</small></span></Link>
        <div className="workspace-label">PROJECT SPACE <span>LOCAL API</span></div>
        <nav className="side-nav" aria-label="Main navigation">
          {nav.map(({ href, label, icon: Icon, code }) => <Link key={href} href={href} className={`nav-link ${path === href ? "active" : ""}`} aria-current={path === href ? "page" : undefined}><span className="nav-code">{code}</span><Icon size={17} strokeWidth={1.8} /><span>{label}</span>{path === href && <span className="nav-active-dot" />}</Link>)}
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-note"><span className="dot dot-red" /> AUTHENTICATED LOCAL SESSION<p>{user?.email ?? "No session"} · {user?.role.toUpperCase() ?? "VIEWER"} · tenant {user?.tenantId ?? "—"}</p></div>
          <div className="build-stamp"><span>FLASK + REACT LOCAL STACK</span><strong>ZT / 0.3.0-local</strong><small>{currentStep.toUpperCase()}</small></div>
        </div>
      </aside>
      <div className="main-column">
        <header className="topbar">
          <div className="breadcrumb"><span>ZEROTRACE</span><ArrowRight size={13} /><strong>{nav.find((item) => item.href === path)?.label.toUpperCase() ?? "NOT FOUND"}</strong></div>
          <div className="topbar-actions">
            <span className={`live-pill ${isConnected ? "live-online" : "live-offline"}`}><i /> {connectionLabel}</span>
            <span className="user-pill" title={`${user?.email} · ${user?.role}`}><UserRound size={13} /> <b>{user?.email}</b><em>{user?.role.toUpperCase()}</em></span>
            {isDemoPage && canOperate && <button className="button button-primary button-small" onClick={runAll} disabled={!isConnected || stage >= 3 || isProcessing}><ArrowRight size={15} />{isProcessing ? "Saving…" : stage === 0 ? "Advance demo" : stage >= 3 ? "Demo complete" : "Advance demo"}</button>}
            {isDemoPage && canOperate && <button className="icon-button" onClick={() => void reset()} disabled={!isConnected || isProcessing} title="Reset persisted demo scenario" aria-label="Reset scenario"><RefreshCcw size={16} /></button>}
            <button className="icon-button" onClick={() => void logout()} title="Sign out" aria-label="Sign out"><LogOut size={16} /></button>
          </div>
        </header>
        {connectionError && <div className="api-error-banner" role="alert"><div><b>Backend connection issue</b><span>{connectionError}</span></div><button onClick={() => void refresh()}>Retry</button></div>}
        <main className="page-content">{children}</main>
        <footer className="page-footer"><span><span className="dot dot-red" /> LIVE READS REQUIRE AN APPROVED SCOPE</span><span>ZERO TRACE · LOCAL LOOPBACK INSTALLATION</span></footer>
      </div>
    </div>
  );
}
