import { useState } from "react";
import { CheckCircle2, Circle, Compass, X } from "lucide-react";
import { useAuth } from "../lib/auth";
import { go } from "../lib/hooks";

const KEY = "agl.tour.v1";

function load(): { hidden: boolean; done: string[] } {
  try {
    return JSON.parse(localStorage.getItem(KEY) || "") as { hidden: boolean; done: string[] };
  } catch {
    return { hidden: false, done: [] };
  }
}

function save(v: { hidden: boolean; done: string[] }) {
  try { localStorage.setItem(KEY, JSON.stringify(v)); } catch { /* storage unavailable: keep in memory */ }
}

export function GuidedTour({ topIncident, topSource }: { topIncident?: string; topSource?: string }) {
  const { me } = useAuth();
  const [st, setSt] = useState(load);
  if (st.hidden) {
    return <button className="flex items-center gap-1 text-[12px] text-signal hover:underline" onClick={() => { const v = { ...st, hidden: false }; setSt(v); save(v); }}><Compass size={13} /> Show the guided tour</button>;
  }
  const analyst = [
    { id: "a1", label: "Open the top incident and read why it is prioritised", run: () => go("incidents", { id: topIncident }) },
    { id: "a2", label: "Step through the time-ordered attack path; click any step to see its raw log record", run: () => go("paths", { source: topSource }) },
    { id: "a3", label: "Check the blast radius: suspected movement vs mere reachability", run: () => go("blast", { entity: topSource }) },
    { id: "a4", label: "Test a containment action at the time you would have acted", run: () => go("incidents", { id: topIncident, tab: "containment" }) },
    { id: "a5", label: "Open the regulator-ready draft and export the evidence-backed report", run: () => go("report", { id: topIncident }) },
  ];
  const admin = [
    { id: "b1", label: "Infrastructure view: affected machines by evidence tier, room and criticality", run: () => go("infrastructure", { id: topIncident }) },
    { id: "b2", label: "Device and physical events from the UNO Q edge sensor (USB, console logins)", run: () => go("infrastructure", { id: topIncident }) },
    { id: "b3", label: "Compare containment options and what each one cuts", run: () => go("infrastructure", { id: topIncident }) },
  ];
  const steps = me?.role === "itadmin" ? [...admin, ...analyst.slice(4)] : [...analyst, ...admin.slice(0, 1)];
  const mark = (id: string, run: () => void) => { const v = { ...st, done: [...new Set([...st.done, id])] }; setSt(v); save(v); run(); };
  return (
    <section aria-label="Guided tour" className="rounded-lg border border-signal/30 bg-signal/5 p-3">
      <div className="mb-2 flex items-center justify-between">
        <h2 className="flex items-center gap-2 text-[13px] font-semibold text-ink-100"><Compass size={14} className="text-signal" />
          Start here: {me?.role === "itadmin" ? "the IT infrastructure admin journey" : "the SOC analyst journey"}</h2>
        <button aria-label="Hide the guided tour" className="rounded p-1 text-ink-400 hover:bg-ink-800" onClick={() => { const v = { ...st, hidden: true }; setSt(v); save(v); }}><X size={14} /></button>
      </div>
      <ol className="grid gap-1 md:grid-cols-2">
        {steps.map((s, i) => (
          <li key={s.id}>
            <button onClick={() => mark(s.id, s.run)} className="flex w-full items-start gap-2 rounded px-2 py-1 text-left text-[12px] hover:bg-ink-850">
              {st.done.includes(s.id) ? <CheckCircle2 size={14} className="mt-0.5 shrink-0 text-ok" /> : <Circle size={14} className="mt-0.5 shrink-0 text-ink-500" />}
              <span><span className="text-ink-400">{i + 1}.</span> {s.label}</span>
            </button>
          </li>
        ))}
      </ol>
    </section>
  );
}
