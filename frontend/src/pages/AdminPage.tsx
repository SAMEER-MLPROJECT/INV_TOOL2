import { useEffect, useState } from "react";
import { MapPin, ShieldCheck, Usb } from "lucide-react";
import { ClockBanner } from "../components/ClockBanner";
import { useInspector } from "../components/Inspector";
import { ClassPill, CritDots, Empty, ErrorBox, Loading, Panel, PriorityPill, TypeIcon } from "../components/ui";
import { api } from "../lib/api";
import { fmtTime, go, setParams, useAsync, type Route } from "../lib/hooks";
import type { BlastClass } from "../lib/types";

const TIER_HELP: Record<string, string> = {
  IN_INCIDENT: "Named in the incident's evidence",
};

export function AdminPage({ route }: { route: Route }) {
  const { data: incs, error: incErr } = useAsync(() => api.incidents(), []);
  const [id, setId] = useState(route.params.get("id") || "");
  useEffect(() => { if (!id && incs?.length) setId(incs[0].id); }, [incs, id]);
  const { data, error, loading } = useAsync(() => (id ? api.admin(id) : Promise.resolve(null)), [id]);
  const { open: inspect } = useInspector();
  if (incErr) return <ErrorBox msg={incErr} />;
  if (!incs) return <Loading />;
  if (!incs.length) return <Empty>No incidents yet. Load data in Settings &amp; Data, or stream events from an edge device.</Empty>;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <label className="text-[12px] text-ink-400" htmlFor="adm-inc">Incident</label>
        <select id="adm-inc" className="rounded-md border border-ink-600 bg-ink-850 px-2 py-1.5 text-[13px]" value={id}
          onChange={(e) => { setId(e.target.value); setParams("infrastructure", { id: e.target.value }); }}>
          {incs.map((i) => <option key={i.id} value={i.id}>{i.id} · {i.priority} · {i.title}</option>)}
        </select>
        <span className="text-[12px] text-ink-400">For IT infrastructure admins: which machines, rooms and devices are involved, and what to cut first.</span>
      </div>
      {error && <ErrorBox msg={error} />}
      {loading && !data && <Loading />}
      {data && (
        <>
          <ClockBanner clock={data.clock} incident={data.incident} />
          <Panel title="Incident summary for infrastructure">
            <ul className="space-y-1.5 text-[13px] leading-relaxed">
              {data.summary.map((s, i) => <li key={i} className={i === 0 ? "font-medium text-ink-100" : "text-ink-300"}>{s}</li>)}
            </ul>
          </Panel>
          <div className="grid gap-4 xl:grid-cols-[1.3fr_1fr]">
            <Panel title={`Affected infrastructure (${data.assets.length})`} bodyClass="p-0">
              <div className="max-h-[460px] overflow-auto">
                <table className="w-full text-[12px]">
                  <thead className="sticky top-0 bg-ink-900 text-left text-ink-400">
                    <tr><th className="px-3 py-2">Asset</th><th className="px-2">Evidence tier</th><th className="px-2">Criticality</th>
                      <th className="px-2">Location</th><th className="px-2">Reached</th><th className="px-2 text-right">Suspicious</th></tr>
                  </thead>
                  <tbody>
                    {data.assets.map((a) => (
                      <tr key={a.id} className="cursor-pointer border-t border-ink-800 hover:bg-ink-850" onClick={() => inspect({ kind: "entity", id: a.id })}>
                        <td className="px-3 py-1.5"><span className="flex items-center gap-2"><TypeIcon type={a.type} size={13} /> {a.name}
                          {a.analyst_status === "confirmed" && <span className="rounded bg-crit/20 px-1 text-[10px] text-crit">confirmed</span>}</span></td>
                        <td className="px-2">{a.tier in TIER_HELP ? <span className="text-[11px] text-ink-300" title={TIER_HELP[a.tier]}>In incident</span> : <ClassPill c={a.tier as BlastClass} />}</td>
                        <td className="px-2"><CritDots n={a.criticality} /></td>
                        <td className="px-2 text-ink-300">{a.location ? <span className="flex items-center gap-1"><MapPin size={11} />{a.location}</span> : "–"}</td>
                        <td className="mono px-2 text-ink-400">{a.reached_at ? fmtTime(a.reached_at, false) : "–"}</td>
                        <td className="tabular px-2 text-right">{a.suspicious_events}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>
            <Panel title={<span className="flex items-center gap-2"><ShieldCheck size={14} /> Containment options (simulated)</span>}>
              {data.containment_options.length === 0 ? <Empty>No containment option could be computed for this incident.</Empty> : (
                <ol className="space-y-2 text-[13px]">
                  {data.containment_options.map((o, i) => (
                    <li key={o.target} className="rounded-md border border-ink-700 p-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-medium">{i + 1}. {o.label}</span>
                        <span className="tabular text-ok">−{o.risk_reduction_pct}% path risk</span>
                      </div>
                      <div className="mt-1 text-[11px] text-ink-400">Disruption cost {o.cost} · protects {o.crown_jewels_protected.length ? o.crown_jewels_protected.map((x) => x.split(":")[1]).join(", ") : "no crown jewel"}</div>
                    </li>
                  ))}
                </ol>
              )}
              <p className="mt-3 text-[11px] text-ink-400">{data.caveat}</p>
              <div className="mt-2 flex gap-3 text-[12px]">
                <button className="text-signal hover:underline" onClick={() => go("incidents", { id: data.incident })}>Open full containment simulator</button>
                <button className="text-signal hover:underline" onClick={() => go("report", { id: data.incident })}>Regulator-ready draft</button>
              </div>
            </Panel>
          </div>
          <Panel title={<span className="flex items-center gap-2"><Usb size={14} /> Device and infrastructure events ({data.infrastructure_events.length})</span>} bodyClass="p-0">
            {data.infrastructure_events.length === 0 ? <div className="p-4"><Empty>No device or infrastructure events.</Empty></div> : (
              <div className="max-h-[420px] overflow-auto">
                <table className="w-full text-[12px]">
                  <thead className="sticky top-0 bg-ink-900 text-left text-ink-400">
                    <tr><th className="px-3 py-2">Time (UTC)</th><th className="px-2">Kind</th><th className="px-2">What happened</th><th className="px-2">Where</th><th className="px-2">Severity</th><th className="px-2">Link</th></tr>
                  </thead>
                  <tbody>
                    {data.infrastructure_events.map((e) => (
                      <tr key={e.uid} className="cursor-pointer border-t border-ink-800 hover:bg-ink-850" onClick={() => inspect({ kind: "event", id: e.uid })}>
                        <td className="mono px-3 py-1.5 text-ink-400">{fmtTime(e.timestamp)}</td>
                        <td className="px-2">{e.kind === "physical" ? <span className="rounded bg-signal/15 px-1.5 text-[10px] text-signal">physical</span> : e.kind}</td>
                        <td className="px-2">{e.description}</td>
                        <td className="px-2 text-ink-300">{e.location || "–"}</td>
                        <td className="tabular px-2">{e.severity.toFixed(2)}</td>
                        <td className="px-2 text-[11px] text-ink-400">{e.in_incident ? "in incident" : e.same_room_as_incident_assets ? "same room as incident assets" : ""}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="border-t border-ink-800 px-3 py-2 text-[11px] text-ink-400">
              Physical events come from signed edge sensors. A USB insertion or console login is evidence to check, not proof of an attack.
            </p>
          </Panel>
          {incs.find((i) => i.id === data.incident) && <div className="text-[11px] text-ink-500">Incident priority: <PriorityPill priority={incs.find((i) => i.id === data.incident)!.priority} /></div>}
        </>
      )}
    </div>
  );
}
