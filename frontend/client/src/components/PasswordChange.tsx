import { useState, type FormEvent } from "react";
import { CircleAlert, KeyRound, ShieldCheck } from "lucide-react";
import { Panel } from "@/components/DemoPrimitives";
import { apiRequest } from "@/lib/api";

export default function PasswordChange() {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setNotice(null);
    if (newPassword !== confirmPassword) {
      setError("The new passwords do not match.");
      return;
    }
    if (newPassword.length < 12) {
      setError("Password must be between 12 and 256 characters.");
      return;
    }
    setBusy(true);
    try {
      await apiRequest<{ ok: boolean; revokedOthers: boolean }>("/auth/password", {
        method: "POST",
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setNotice("Password updated. Other active sessions were revoked.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The password could not be changed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel
      title="Operator password"
      subtitle="Change the password for the signed-in local account. Other active sessions are revoked."
      tag="ACCOUNT SECURITY"
    >
      <form onSubmit={(event) => void submit(event)}>
        <div className="field-grid">
          <div className="field field-wide">
            <label htmlFor="password-current">Current password</label>
            <input
              id="password-current"
              type="password"
              autoComplete="current-password"
              value={currentPassword}
              onChange={(event) => setCurrentPassword(event.target.value)}
              required
            />
          </div>
          <div className="field">
            <label htmlFor="password-new">New password</label>
            <input
              id="password-new"
              type="password"
              autoComplete="new-password"
              minLength={12}
              maxLength={256}
              value={newPassword}
              onChange={(event) => setNewPassword(event.target.value)}
              required
            />
          </div>
          <div className="field">
            <label htmlFor="password-confirm">Confirm new password</label>
            <input
              id="password-confirm"
              type="password"
              autoComplete="new-password"
              minLength={12}
              maxLength={256}
              value={confirmPassword}
              onChange={(event) => setConfirmPassword(event.target.value)}
              required
            />
          </div>
        </div>

        {error && <div className="console-alert" role="alert"><CircleAlert size={15} /><span>{error}</span></div>}
        {notice && <div className="console-alert success" role="status"><ShieldCheck size={15} /><span>{notice}</span></div>}

        <div className="form-actions">
          <button
            className="button button-primary"
            type="submit"
            disabled={busy || !currentPassword || !newPassword || !confirmPassword}
          >
            <KeyRound size={15} />{busy ? "Updating password…" : "Update password"}
          </button>
        </div>
      </form>

      <div className="small-warning">
        <ShieldCheck size={15} />
        <span>Use at least 12 characters. The password is hashed server-side and is never stored in the browser.</span>
      </div>
    </Panel>
  );
}
