import { useEffect, useRef, useState } from "react";
import { Activity, Copy, Database, RefreshCcw, Save, Trash2, Upload, Usb, Users } from "lucide-react";
import { Button, ErrorBox, Field, Loading, Panel, inputCls } from "../components/ui";
import { api } from "../lib/api";
import { ROLE_LABEL, useAuth } from "../lib/auth";
import { fmtBytes, fmtTime, useAsync, useDataVersion } from "../lib/hooks";
import type { FileSummary, Settings } from "../lib/types";

const WEIGHT_LABELS: Record<string, string> = {
  criticality: "Asset criticality", suspicion: "Event suspicion", corroboration: "Independent corroboration",
  evidence_quality: "Evidence quality", path_length: "Path compactness", recency: "Recency",
};

export function SettingsPage() {
  const { bump } = useDataVersion();
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const flash = (ok: boolean, text: string) => { setMsg({ ok, text }); setTimeout(() => setMsg(null), 6000); };
  return (
    <div className="space-y-4">
      {msg && <div role="status" className={`rounded-md border px-3 py-2 text-sm ${msg.ok ? "border-ok/40 bg-ok/10 text-ok" : "border-crit/40 bg-crit/10 text-crit"}`}>{msg.text}</div>}
      <div className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
        <DataPanel onDone={(ok, t) => { flash(ok, t); bump(); }} />
        <div className="space-y-4">
          <BackendPanel onDone={flash} />
          <HealthPanel />
        </div>
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <DevicesPanel onDone={flash} />
        <UsersPanel onDone={flash} />
      </div>
      <SettingsForm onDone={(ok, t) => { flash(ok, t); if (ok) bump(); }} />
      <FilesPanel />
      <RulesPanel />
    </div>
  );
}

function DataPanel({ onDone }: { onDone: (ok: boolean, text: string) => void }) {
  const { can } = useAuth();
  const { data: sources } = useAsync(() => api.sources(), []);
  const [files, setFiles] = useState<File[]>([]);
  const [sourceType, setSourceType] = useState("");
  const [mode, setMode] = useState<"append" | "replace">("append");
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState<FileSummary[] | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const act = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true);
    try { await fn(); onDone(true, ok); } catch (e) { onDone(false, (e as Error).message); } finally { setBusy(false); }
  };
  return (
    <Panel title={<span className="flex items-center gap-2"><Database size={14} /> Data management</span>}>
      <div className="mb-4 flex flex-wrap gap-2">
        <Button disabled={busy || !can("manage")} title={can("manage") ? undefined : "Only the analyst role can reset data"} onClick={() => act(async () => setResults((await api.loadSample()).files), "Synthetic sample dataset reloaded.")}><RefreshCcw size={14} /> Reset to sample dataset</Button>
        <Button disabled={busy || !can("manage")} title="A real attack recorded by OTRF: Windows/Sysmon logs, Zeek logs and a packet capture (MIT licence)"
          onClick={() => act(async () => setResults((await api.loadReal()).files), "Real attack dataset loaded (OTRF LSASS_campaign_03).")}>
          <Database size={14} /> Load real attack data (OTRF)</Button>
        <Button variant="danger" disabled={busy || !can("manage")} title={can("manage") ? undefined : "Only the analyst role can clear data"} onClick={() => confirm("Remove all of this organisation's data, including what is stored in Neo4j?") && act(() => api.clear(), "All data cleared.")}><Trash2 size={14} /> Clear all data</Button>
      </div>
      <div className="rounded-md border border-dashed border-ink-600 p-3">
        <div className="mb-2 text-[13px] font-medium">Import dataset</div>
        <div className="grid gap-3 md:grid-cols-[1.3fr_1fr_1fr]">
          <Field label="Files (.csv, .json, .jsonl · max 20 MB each)">
            <input ref={input} aria-label="Dataset files" type="file" multiple accept=".csv,.json,.jsonl,.ndjson,.log,.pcap,.pcapng,.cap" onChange={(e) => setFiles([...(e.target.files || [])])}
              className="block w-full text-xs text-ink-300 file:mr-2 file:rounded file:border-0 file:bg-ink-700 file:px-2 file:py-1 file:text-ink-100" />
          </Field>
          <Field label="Source type">
            <select className={inputCls} value={sourceType} onChange={(e) => setSourceType(e.target.value)}>
              <option value="">Auto-detect from fields</option>
              {sources?.map((s) => <option key={s.name} value={s.name}>{s.label}</option>)}
            </select>
          </Field>
          <Field label="Mode">
            <select className={inputCls} value={mode} onChange={(e) => setMode(e.target.value as "append")}>
              <option value="append">Append to loaded data</option>
              <option value="replace">Replace loaded data</option>
            </select>
          </Field>
        </div>
        <div className="mt-3 flex items-center gap-3">
          <Button variant="primary" disabled={busy || files.length === 0} onClick={() => act(async () => {
            const r = await api.upload(files, sourceType, mode);
            setResults(r.files);
            if (input.current) input.current.value = "";
            setFiles([]);
            const failed = r.files.filter((f) => f.error);
            if (failed.length) throw new Error(failed.map((f) => `${f.file_name}: ${f.error}`).join("; "));
          }, "Upload processed.")}><Upload size={14} /> Upload &amp; rebuild graph</Button>
          <span className="text-[11px] text-ink-400">Files are parsed as data only and never executed. Field schemas per source type are listed below.</span>
        </div>
        {sources && (
          <details className="mt-3 text-[11px] text-ink-400">
            <summary className="cursor-pointer text-ink-300">Supported source schemas</summary>
            <ul className="mt-1 space-y-0.5">{sources.map((s) => <li key={s.name}><span className="mono text-ink-200">{s.name}</span>: {s.label}: requires <span className="mono">{s.required_fields.join(", ")}</span></li>)}</ul>
          </details>
        )}
      </div>
      {results && (
        <div className="mt-3 space-y-1 text-xs">
          {results.map((r) => (
            <div key={r.file_name} className={r.error ? "text-crit" : "text-ink-300"}>
              <span className="mono">{r.file_name}</span>: {r.error ? r.error : `${r.source_system} · ${r.accepted} used, ${r.filtered ?? 0} filtered, ${r.detections ?? 0} detections, ${r.rejected} rejected, ${r.duplicates} duplicate, ${r.conflicts} conflict`}
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

function BackendPanel({ onDone }: { onDone: (ok: boolean, text: string) => void }) {
  const { can } = useAuth();
  const { data: b, reload } = useAsync(() => api.backend(), []);
  const { data: counts } = useAsync(() => (b?.persistent && b.neo4j.connected ? api.neo4jCounts() : Promise.resolve(null)), [b?.neo4j.connected, b?.persistent]);
  const [busy, setBusy] = useState(false);
  if (!b) return <Loading />;
  const state = !b.persistent ? ["text-ink-300", "In-memory only: data is lost on restart"]
    : b.persisted ? ["text-ok", "All evidence persisted in Neo4j"] : ["text-crit", `NOT persisted: ${b.pending_items} item(s) held in memory`];
  return (
    <Panel title="Evidence store">
      <dl className="grid grid-cols-[150px_1fr] gap-y-1 text-[13px]">
        <dt className="text-ink-400">Persistence</dt><dd className={state[0]}>{state[1]}</dd>
        <dt className="text-ink-400">Analysis engine</dt><dd>{b.local_engine}</dd>
        <dt className="text-ink-400">Neo4j</dt><dd>{b.neo4j.configured ? `${b.neo4j.uri_host} / ${b.neo4j.database}` : "not configured"}</dd>
        {b.neo4j.server && <><dt className="text-ink-400">Server</dt><dd className="mono">{b.neo4j.server.name} {b.neo4j.server.versions?.join(", ")} {b.neo4j.server.edition}</dd></>}
        <dt className="text-ink-400">Status</dt><dd className={b.neo4j.connected ? "text-ok" : "text-ink-300"}>{b.neo4j.message}</dd>
        {b.neo4j.cypher25 != null && <><dt className="text-ink-400">Temporal path query</dt><dd>{b.neo4j.cypher25 ? "Cypher 25 allReduce (pruned during expansion)" : "variable-length match (Cypher 25 unavailable)"}</dd></>}
        {b.neo4j.restored_files != null && <><dt className="text-ink-400">Restored at start</dt><dd>{b.neo4j.restored_files} source file(s) reloaded from Neo4j</dd></>}
        {counts && <><dt className="text-ink-400">Stored in Neo4j</dt><dd className="tabular">{counts.events} events ({counts.conflicting} conflicting copies kept) · {counts.files} files · {counts.entities} entities · {counts.relationships} relationships · {counts.incidents} incidents</dd></>}
      </dl>
      <div className="mt-3 flex items-center gap-2">
        <Button disabled={!b.neo4j.configured || busy || !can("manage")} onClick={async () => {
          setBusy(true);
          try { const r = await api.neo4jSync(); onDone(r.persisted, r.neo4j.message); reload(); } catch (e) { onDone(false, (e as Error).message); } finally { setBusy(false); }
        }}>Reconnect &amp; write pending</Button>
      </div>
      <p className="mt-2 text-[11px] leading-snug text-ink-400">
        With <span className="mono">AGL_GRAPH_BACKEND=neo4j</span> every upload, stream batch and analyst verdict is written to Neo4j as it happens and the
        workspace is rebuilt from Neo4j after a restart. If Neo4j is unreachable the app keeps working in memory and says so here.
      </p>
    </Panel>
  );
}

function HealthPanel() {
  const { data, error, reload, loading } = useAsync(() => api.health(), []);
  return (
    <Panel title={<span className="flex items-center gap-2"><Activity size={14} /> Application health</span>} actions={<Button variant="ghost" onClick={reload} disabled={loading}>Check</Button>}>
      {error ? <ErrorBox msg={error} /> : !data ? <Loading /> : (
        <dl className="grid grid-cols-[140px_1fr] gap-y-1 text-[13px]">
          <dt className="text-ink-400">API</dt><dd className="text-ok">{data.status}</dd>
          <dt className="text-ink-400">Version</dt><dd className="mono">{data.version}</dd>
          <dt className="text-ink-400">Authentication</dt><dd>{data.auth}</dd>
        </dl>
      )}
    </Panel>
  );
}

function DevicesPanel({ onDone }: { onDone: (ok: boolean, text: string) => void }) {
  const { can, me } = useAuth();
  const { data, reload } = useAsync(() => api.devices(), []);
  const [name, setName] = useState("UNOQ-RACK-01");
  const [loc, setLoc] = useState("Server room A");
  const [created, setCreated] = useState<{ id: string; secret: string } | null>(null);
  const cmd = created ? `AGL_URL=${window.location.origin} AGL_DEVICE_ID=${created.id} AGL_DEVICE_SECRET=${created.secret} AGL_ALLOW_USB=046d:0825 python3 agent.py` : "";
  return (
    <Panel title={<span className="flex items-center gap-2"><Usb size={14} /> Edge devices (Arduino UNO Q)</span>}>
      {!me?.auth ? <p className="text-[12px] text-ink-400">Edge devices need authentication enabled.</p> : <>
        <ul className="mb-3 space-y-1 text-[12px]">
          {(data || []).map((d) => <li key={d.id} className="flex justify-between"><span><span className="mono text-ink-100">{d.name}</span> <span className="text-ink-400">· {d.location}</span></span><span className="text-ink-400">{d.last_seq ? `${d.last_seq} envelopes received` : "never seen"}</span></li>)}
          {data && data.length === 0 && <li className="text-ink-400">No devices registered.</li>}
        </ul>
        {can("manage") && (
          <form className="grid grid-cols-[1fr_1fr_auto] items-end gap-2" onSubmit={async (e) => {
            e.preventDefault();
            try { const d = await api.addDevice(name, loc); setCreated({ id: d.id, secret: d.secret }); reload(); onDone(true, `Device ${d.name} registered. Copy its secret now.`); }
            catch (ex) { onDone(false, (ex as Error).message); }
          }}>
            <Field label="Device name"><input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} /></Field>
            <Field label="Location (server-side, the device cannot change it)"><input className={inputCls} value={loc} onChange={(e) => setLoc(e.target.value)} /></Field>
            <Button type="submit">Register</Button>
          </form>
        )}
        {created && (
          <div className="mt-3 rounded-md border border-high/40 bg-high/10 p-2 text-[11px]">
            <div className="mb-1 font-medium text-ink-100">Shown once. Run on the UNO Q (or put the values in edge_config.json):</div>
            <code className="block break-all text-ink-200">{cmd}</code>
            <button className="mt-1 flex items-center gap-1 text-signal hover:underline" onClick={() => navigator.clipboard?.writeText(cmd)}><Copy size={11} /> copy</button>
          </div>
        )}
        <p className="mt-2 text-[11px] text-ink-400">Each envelope is HMAC-signed with the device key and hash-chained to the previous one. Bad signatures and replays are rejected; gaps and broken chains are recorded as integrity events.</p>
      </>}
    </Panel>
  );
}

function UsersPanel({ onDone }: { onDone: (ok: boolean, text: string) => void }) {
  const { can, me } = useAuth();
  const { data, reload } = useAsync(() => api.orgUsers(), []);
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [role, setRole] = useState("itadmin");
  return (
    <Panel title={<span className="flex items-center gap-2"><Users size={14} /> People in {me?.org.name || "this organisation"}</span>}>
      <ul className="mb-3 space-y-1 text-[12px]">
        {(data || []).map((x) => <li key={x.username} className="flex justify-between"><span className="mono">{x.username}</span><span className="text-ink-400">{ROLE_LABEL[x.role] || x.role}</span></li>)}
      </ul>
      {can("manage") && me?.auth && (
        <form className="grid grid-cols-[1fr_1fr_1fr_auto] items-end gap-2" onSubmit={async (e) => {
          e.preventDefault();
          try { await api.addUser(u, p, role); setU(""); setP(""); reload(); onDone(true, `User ${u} added.`); } catch (ex) { onDone(false, (ex as Error).message); }
        }}>
          <Field label="Username"><input className={inputCls} value={u} onChange={(e) => setU(e.target.value)} required /></Field>
          <Field label="Password (10+)"><input className={inputCls} type="password" value={p} onChange={(e) => setP(e.target.value)} required autoComplete="new-password" /></Field>
          <Field label="Role"><select className={inputCls} value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="analyst">SOC analyst</option><option value="itadmin">IT infrastructure admin</option><option value="viewer">Viewer</option></select></Field>
          <Button type="submit">Add</Button>
        </form>
      )}
    </Panel>
  );
}

function SettingsForm({ onDone }: { onDone: (ok: boolean, text: string) => void }) {
  const { data } = useAsync(() => api.settings(), []);
  const [s, setS] = useState<Settings | null>(null);
  useEffect(() => { if (data) setS(data); }, [data]);
  if (!s) return <Loading />;
  const num = (k: keyof Settings, label: string, hint: string, step = 1) => (
    <Field label={label} hint={hint}>
      <input type="number" step={step} className={inputCls} value={s[k] as number} onChange={(e) => setS({ ...s, [k]: Number(e.target.value) })} />
    </Field>
  );
  const total = Object.values(s.weights).reduce((a, b) => a + b, 0) || 1;
  return (
    <Panel title="Analysis &amp; risk-ranking configuration" actions={
      <>
        <Button variant="ghost" onClick={async () => { try { setS(await api.resetSettings()); onDone(true, "Defaults restored."); } catch (e) { onDone(false, (e as Error).message); } }}>Restore defaults</Button>
        <Button variant="primary" onClick={async () => { try { setS(await api.saveSettings(s)); onDone(true, "Settings saved; analysis recomputed."); } catch (e) { onDone(false, (e as Error).message); } }}><Save size={14} /> Save &amp; recompute</Button>
      </>
    }>
      <div className="grid gap-4 md:grid-cols-4">
        {num("correlation_window_minutes", "Correlation window (min)", "Max gap between linked signals")}
        {num("max_hop_gap_hours", "Max gap between path steps (h)", "0 = unlimited", 0.5)}
        {num("clock_skew_seconds", "Clock-skew tolerance (s)", "Between source systems")}
        {num("suspicion_threshold", "Suspicion threshold", "0 to 1; seeds & 'suspected' tier", 0.05)}
        {num("default_max_hops", "Default max hops", "Incident hypotheses (1 to 8)")}
        {num("max_paths", "Paths returned", "Per search (1 to 100)")}
        {num("search_budget", "Search budget", "Edge expansions per search", 1000)}
        {num("recency_half_life_hours", "Recency half-life (h)", "Relative to newest event", 1)}
      </div>
      <div className="mt-5">
        <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-ink-400">Ranking weights: score = 100 × Σ wₖ·cₖ (weights are normalised to sum to 1)</div>
        <div className="grid gap-3 md:grid-cols-6">
          {Object.keys(WEIGHT_LABELS).map((k) => (
            <Field key={k} label={WEIGHT_LABELS[k]} hint={`effective ${((100 * (s.weights[k] ?? 0)) / total).toFixed(0)}%`}>
              <input type="number" step={0.05} min={0} className={inputCls} value={s.weights[k]} onChange={(e) => setS({ ...s, weights: { ...s.weights, [k]: Number(e.target.value) } })} />
            </Field>
          ))}
        </div>
        <p className="mt-2 text-[11px] text-ink-400">Scores are deterministic triage rankings for ordering work. They are not calibrated probabilities of compromise. See docs/METHODOLOGY.md for every formula.</p>
      </div>
    </Panel>
  );
}

function FilesPanel() {
  const { data } = useAsync(() => api.datasets(), []);
  if (!data) return null;
  return (
    <Panel title={`Loaded files (${data.files.length})`} bodyClass="p-0">
      <table className="w-full text-[12px]">
        <thead className="text-left text-[10px] uppercase tracking-wider text-ink-400">
          <tr><th className="px-4 py-2">File</th><th>Detected source</th><th>Size</th><th>Read</th><th>Used</th><th title="Understood but not used; reasons listed in Notes">Filtered</th><th>Detections</th><th>Rejected</th><th>Dup.</th><th>Conflict</th><th>Notes</th><th className="pr-4">Time range</th></tr>
        </thead>
        <tbody className="divide-y divide-ink-700">
          {data.files.map((f) => {
            const grouped = new Map<string, { level: string; rows: (number | null)[] }>();
            f.issues.forEach((i) => {
              const key = i.message.replace(/\b(AUTH|FW|EDR|DNS|DB)-\d+\b/g, "<id>");
              const g = grouped.get(key) || { level: i.level, rows: [] };
              g.rows.push(i.source_row);
              grouped.set(key, g);
            });
            return (
              <tr key={f.file_name + f.loaded_at} className="align-top">
                <td className="mono px-4 py-1.5">{f.file_name}</td>
                <td className="text-ink-300">{f.source_system}</td>
                <td className="tabular text-ink-400">{fmtBytes(f.size_bytes)}</td>
                <td className="tabular">{f.records_read}</td>
                <td className="tabular">{f.accepted}</td>
                <td className="tabular text-ink-400">{f.filtered ?? 0}</td>
                <td className={`tabular ${f.detections ? "text-high" : ""}`}>{f.detections ?? 0}</td>
                <td className={`tabular ${f.rejected ? "text-mod" : ""}`}>{f.rejected}</td>
                <td className="tabular">{f.duplicates}</td>
                <td className={`tabular ${f.conflicts ? "text-mod" : ""}`}>{f.conflicts}</td>
                <td className="max-w-[360px]">
                  {(f.format_notes || []).map((n) => <div key={n} className={`text-[11px] ${n.startsWith("clock") ? "text-high" : "text-ink-300"}`}>{n}</div>)}
                  {f.filtered ? (
                    <details>
                      <summary className="cursor-pointer text-ink-300">{f.filtered} filtered, by reason</summary>
                      <ul className="mt-1 space-y-0.5 text-[11px] text-ink-400">
                        {Object.entries(f.filtered_reasons || {}).map(([k, v]) => <li key={k}>{v} × {k}</li>)}
                      </ul>
                    </details>
                  ) : null}
                  {grouped.size === 0 ? (f.format_notes?.length || f.filtered ? null : <span className="text-ink-500">-</span>) : (
                    <details>
                      <summary className="cursor-pointer text-ink-300">{f.issues.length} issue(s)</summary>
                      <ul className="mt-1 space-y-0.5 text-[11px]">
                        {[...grouped.entries()].map(([m, g]) => (
                          <li key={m} className={g.level === "error" || g.level === "conflict" ? "text-mod" : "text-ink-400"}>
                            [{g.level}] {m}, row{g.rows.length > 1 ? "s" : ""} {g.rows.slice(0, 6).join(", ")}{g.rows.length > 6 ? ` +${g.rows.length - 6}` : ""}
                          </li>
                        ))}
                      </ul>
                    </details>
                  )}
                </td>
                <td className="mono pr-4 text-[10px] text-ink-400">{fmtTime(f.first_event)}<br />{fmtTime(f.last_event)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </Panel>
  );
}

function RulesPanel() {
  const { data } = useAsync(() => api.rules(), []);
  if (!data) return null;
  return (
    <Panel title="Rule catalogue (every graph element, suspicion value and correlation link cites one of these)">
      <div className="grid gap-2 md:grid-cols-2">
        {Object.entries(data).map(([id, r]) => (
          <div key={id} className="rounded border border-ink-700 bg-ink-850 px-3 py-2">
            <div className="flex items-center gap-2"><span className="mono text-[11px] text-signal">{id}</span><span className="text-[13px] font-medium">{r.title}</span><span className="ml-auto text-[10px] uppercase tracking-wider text-ink-500">{r.kind}</span></div>
            <p className="mt-0.5 text-[12px] leading-snug text-ink-300">{r.description}</p>
          </div>
        ))}
      </div>
    </Panel>
  );
}
