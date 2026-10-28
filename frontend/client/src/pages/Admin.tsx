import { useState } from "react";
import { Cable, Crosshair, Database, KeyRound, Layers, ShieldAlert } from "lucide-react";
import { PageHeading, Panel, StateTag } from "@/components/DemoPrimitives";
import EngineConnection from "@/components/EngineConnection";
import PasswordChange from "@/components/PasswordChange";
import { useAuth } from "@/lib/auth";
import Architecture from "@/pages/Architecture";
import DatabasePage from "@/pages/Database";
import Targets from "@/pages/Targets";

type AdminTab = "engine" | "architecture" | "targets" | "database" | "account";

const tabs: Array<{ id: AdminTab; label: string; icon: typeof Cable }> = [
  { id: "engine", label: "Engine connection", icon: Cable },
  { id: "architecture", label: "Architecture", icon: Layers },
  { id: "targets", label: "Targets & scope", icon: Crosshair },
  { id: "database", label: "Database & events", icon: Database },
  { id: "account", label: "Account", icon: KeyRound },
];

export default function Admin() {
  const { user } = useAuth();
  const [tab, setTab] = useState<AdminTab>("engine");

  if (user?.role !== "admin") {
    return <>
      <PageHeading
        eyebrow="ADMIN / 05 · CONTROL PLANE"
        title="Admin"
        description="The control plane is restricted to the local administrator account."
        actions={<StateTag tone="red">ADMIN ONLY</StateTag>}
      />
      <Panel title="Admin access required" subtitle="This session is authenticated but not authorized for control-plane changes." tag="403">
        <div className="empty-console">
          <ShieldAlert size={22} />
          <b>Your role is {user?.role ?? "unknown"}</b>
          <p>Ask the local administrator to promote this account or sign in with an admin session.</p>
        </div>
      </Panel>
    </>;
  }

  return <>
    <PageHeading
      eyebrow="ADMIN / 05 · CONTROL PLANE"
      title="Admin"
      description="Device context, engine connection, authorized targets, the evidence store, and the local operator account. Everything stays on this loopback installation."
      actions={<StateTag tone="green">LOCAL ADMIN</StateTag>}
    />

    <div className="tab-bar admin-tab-bar" role="tablist" aria-label="Admin sections">
      {tabs.map(({ id, label, icon: Icon }) => (
        <button
          key={id}
          className={`tab-button ${tab === id ? "selected" : ""}`}
          onClick={() => setTab(id)}
          role="tab"
          aria-selected={tab === id}
          type="button"
        >
          <Icon size={15} />{label}
        </button>
      ))}
    </div>

    {tab === "engine" && <EngineConnection />}
    {tab === "architecture" && <Architecture embedded />}
    {tab === "targets" && <Targets embedded />}
    {tab === "database" && <DatabasePage embedded />}
    {tab === "account" && <PasswordChange />}
  </>;
}
