import { useState, type FormEvent } from "react";
import { LogIn, UserPlus } from "lucide-react";
import { Button, ErrorBox, Field, inputCls } from "../components/ui";
import { api } from "../lib/api";
import { ROLE_LABEL, useAuth } from "../lib/auth";
import { useAsync } from "../lib/hooks";

export function LoginPage() {
  const { refresh } = useAuth();
  const { data: cfg } = useAsync(() => api.authConfig(), []);
  const [mode, setMode] = useState<"login" | "signup">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [org, setOrg] = useState("");
  const [sample, setSample] = useState(true);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      if (mode === "login") await api.login(username, password);
      else await api.signup(org, username, password, sample);
      await refresh();
      window.location.hash = "/overview";
    } catch (ex) {
      setErr((ex as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const useDemo = (u: string) => {
    setMode("login");
    setUsername(u);
    if (cfg?.demo_password) setPassword(cfg.demo_password);
  };

  return (
    <div className="flex min-h-full items-center justify-center p-6">
      <div className="grid w-full max-w-4xl gap-6 md:grid-cols-[1.1fr_1fr]">
        <section className="flex flex-col justify-center">
          <div className="mb-3 flex items-center gap-2">
            <svg width="30" height="30" viewBox="0 0 32 32" aria-hidden><g stroke="#7cc4ff" strokeWidth="2.2" fill="none"><path d="M8 22 L16 10 L24 20" /><circle cx="8" cy="22" r="3" fill="#111419" /><circle cx="16" cy="10" r="3" fill="#111419" /><circle cx="24" cy="20" r="3.5" fill="#f08c3a" stroke="#f08c3a" /></g></svg>
            <h1 className="text-xl font-semibold">AttackGraph Lens</h1>
          </div>
          <p className="text-[15px] text-ink-200">Who was reached, in what order, and how do we know?</p>
          <p className="mt-3 text-[13px] leading-relaxed text-ink-400">
            Evidence-backed attack paths, blast radius and regulator-ready incident drafts for small SOC teams.
            Every conclusion links back to the log record, file and row it came from.
          </p>
          {cfg && cfg.demo_accounts.length > 0 && (
            <div className="mt-5 rounded-lg border border-ink-700 bg-ink-900 p-3">
              <div className="mb-2 text-[12px] font-medium text-ink-200">Evaluator accounts (synthetic data only)</div>
              <ul className="space-y-1 text-[12px]">
                {cfg.demo_accounts.map((a) => (
                  <li key={a.username} className="flex items-center justify-between gap-2">
                    <span><span className="mono text-ink-100">{a.username}</span> <span className="text-ink-400">· {ROLE_LABEL[a.role] || a.role} · {a.org}</span></span>
                    <button className="text-signal hover:underline" onClick={() => useDemo(a.username)}>use</button>
                  </li>
                ))}
              </ul>
              {cfg.demo_password && <div className="mt-2 text-[11px] text-ink-400">Password for all evaluator accounts: <span className="mono text-ink-200">{cfg.demo_password}</span></div>}
            </div>
          )}
        </section>

        <form onSubmit={submit} className="rounded-lg border border-ink-700 bg-ink-900 p-5" aria-label={mode === "login" ? "Sign in" : "Create workspace"}>
          <div className="mb-4 flex gap-1 rounded-md bg-ink-850 p-1 text-[13px]">
            <button type="button" onClick={() => setMode("login")} className={`flex-1 rounded px-3 py-1.5 ${mode === "login" ? "bg-ink-700 text-ink-100" : "text-ink-400"}`}>Sign in</button>
            {cfg?.signup && <button type="button" onClick={() => setMode("signup")} className={`flex-1 rounded px-3 py-1.5 ${mode === "signup" ? "bg-ink-700 text-ink-100" : "text-ink-400"}`}>Create workspace</button>}
          </div>
          <div className="space-y-3">
            {mode === "signup" && (
              <Field label="Organisation" hint="Your data is isolated from every other organisation.">
                <input className={inputCls} value={org} onChange={(e) => setOrg(e.target.value)} required minLength={2} maxLength={60} autoComplete="organization" />
              </Field>
            )}
            <Field label="Username">
              <input className={inputCls} value={username} onChange={(e) => setUsername(e.target.value)} required autoComplete="username" />
            </Field>
            <Field label="Password" hint={mode === "signup" ? "At least 10 characters." : undefined}>
              <input className={inputCls} type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete={mode === "login" ? "current-password" : "new-password"} />
            </Field>
            {mode === "signup" && (
              <label className="flex items-center gap-2 text-[12px] text-ink-300">
                <input type="checkbox" checked={sample} onChange={(e) => setSample(e.target.checked)} /> Start with the synthetic sample incident
              </label>
            )}
            {err && <ErrorBox msg={err} />}
            <Button type="submit" variant="primary" disabled={busy} className="w-full justify-center">
              {mode === "login" ? <><LogIn size={14} /> Sign in</> : <><UserPlus size={14} /> Create workspace</>}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
