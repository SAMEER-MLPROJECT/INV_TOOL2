import { useEffect, useState } from "react";
import { Download, FileCheck } from "lucide-react";
import { ClockBanner } from "../components/ClockBanner";
import { useInspector } from "../components/Inspector";
import { Empty, ErrorBox, Loading, Panel, PriorityPill } from "../components/ui";
import { api } from "../lib/api";
import { setParams, useAsync, type Route } from "../lib/hooks";

export function ReportPage({ route }: { route: Route }) {
  const { data: incs, error: incErr } = useAsync(() => api.incidents(), []);
  const [id, setId] = useState(route.params.get("id") || "");
  const [form, setForm] = useState("cert_in");
  useEffect(() => { if (!id && incs?.length) setId(incs[0].id); }, [incs, id]);
  const { data, error, loading } = useAsync(() => (id ? api.regulatory(id) : Promise.resolve(null)), [id]);
  const { open: inspect } = useInspector();
  if (incErr) return <ErrorBox msg={incErr} />;
  if (!incs) return <Loading />;
  if (!incs.length) return <Empty>No incidents yet.</Empty>;
  const f = data?.forms[form];
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <label className="text-[12px] text-ink-400" htmlFor="rep-inc">Incident</label>
        <select id="rep-inc" className="rounded-md border border-ink-600 bg-ink-850 px-2 py-1.5 text-[13px]" value={id}
          onChange={(e) => { setId(e.target.value); setParams("report", { id: e.target.value }); }}>
          {incs.map((i) => <option key={i.id} value={i.id}>{i.id} · {i.priority} · {i.title}</option>)}
        </select>
        {data && <PriorityPill priority={data.priority} />}
        {id && (
          <span className="ml-auto flex gap-2 text-[12px]">
            {(["html", "md", "json"] as const).map((fmt) => (
              <a key={fmt} href={api.reportUrl(id, fmt)} className="flex items-center gap-1 rounded-md border border-ink-600 px-2 py-1 hover:bg-ink-800"><Download size={12} /> {fmt.toUpperCase()}</a>
            ))}
          </span>
        )}
      </div>
      {error && <ErrorBox msg={error} />}
      {loading && !data && <Loading />}
      {data && f && (
        <>
          <ClockBanner clock={data.clock} incident={data.incident} />
          <div className="rounded-md border border-signal/30 bg-signal/5 px-3 py-2 text-[12px] text-ink-200">
            <FileCheck size={13} className="mr-1 inline text-signal" /> {data.status} Each value links to the evidence it came from; anything the graph cannot know is marked for the reporting officer.
          </div>
          <div className="flex gap-1 rounded-md bg-ink-900 p-1 text-[13px]" role="tablist">
            {Object.entries(data.forms).map(([k, v]) => (
              <button key={k} role="tab" aria-selected={form === k} onClick={() => setForm(k)}
                className={`rounded px-3 py-1.5 ${form === k ? "bg-ink-700 text-ink-100" : "text-ink-400 hover:text-ink-200"}`}>{v.title.split(" (")[0].split(":")[0]}</button>
            ))}
          </div>
          <Panel title={f.title} bodyClass="p-0">
            <table className="w-full text-[12px]">
              <thead className="text-left text-ink-400"><tr><th className="w-[180px] px-3 py-2">Field</th><th className="px-2">Value</th><th className="w-[260px] px-2">Evidence</th></tr></thead>
              <tbody>
                {f.fields.map((k) => {
                  const fld = data.fields[k];
                  const officer = JSON.stringify(fld.value).includes("officer to");
                  return (
                    <tr key={k} className="border-t border-ink-800 align-top">
                      <td className="px-3 py-2 font-medium capitalize text-ink-200">{k.replace(/_/g, " ")}<div className="mt-0.5 text-[10px] font-normal normal-case text-ink-500">{fld.basis}</div></td>
                      <td className={`px-2 py-2 ${officer ? "text-high" : ""}`}>
                        {Array.isArray(fld.value) ? <ul className="list-disc space-y-0.5 pl-4">{fld.value.map((v, i) => <li key={i}>{v}</li>)}</ul> : fld.value}
                      </td>
                      <td className="px-2 py-2">
                        <div className="flex flex-wrap gap-1">
                          {fld.evidence.slice(0, 8).map((u) => (
                            <button key={u} onClick={() => inspect({ kind: "event", id: u })} className="mono rounded bg-ink-800 px-1.5 py-0.5 text-[10px] text-signal hover:bg-ink-700">{u.split(":")[1] || u}</button>
                          ))}
                          {fld.evidence.length > 8 && <span className="text-[10px] text-ink-400">+{fld.evidence.length - 8} more</span>}
                          {fld.evidence.length === 0 && <span className="text-[10px] text-ink-500">–</span>}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </Panel>
          <Panel title="Evidence files and sources">
            <ul className="space-y-1 text-[12px]">
              {data.evidence_files.map((x) => <li key={x.file_name}><span className="text-ink-200">{x.file_name}</span> <span className="mono text-[10px] text-ink-500">sha256 {x.sha256}</span></li>)}
            </ul>
            <ul className="mt-3 list-disc space-y-0.5 pl-4 text-[11px] text-ink-400">{data.sources.map((s) => <li key={s}>{s}</li>)}</ul>
          </Panel>
        </>
      )}
    </div>
  );
}
