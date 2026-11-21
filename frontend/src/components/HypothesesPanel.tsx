import { useInspector } from "./Inspector";
import type { HypothesisRanking } from "../lib/types";

const TONE: Record<string, string> = {
  "best supported": "text-ok", plausible: "text-ink-200", "not supported": "text-ink-400", "inconsistent with the evidence": "text-crit",
};

export function HypothesesPanel({ h }: { h: HypothesisRanking }) {
  const { open } = useInspector();
  const max = Math.max(1, ...h.hypotheses.map((x) => Math.abs(x.score)));
  const chip = (u: string) => (
    <button key={u} onClick={() => open({ kind: "event", id: u })} className="mono rounded bg-ink-800 px-1 py-0.5 text-[10px] text-signal hover:bg-ink-700">
      {u.includes(":") ? u.split(":").slice(-1)[0].slice(0, 14) : u}
    </button>
  );
  return (
    <div className="space-y-3">
      <p className="text-[13px] text-ink-100">{h.summary}</p>
      {h.next_checks.length > 0 && <p className="text-[12px] text-ink-300">Check next: {h.next_checks.join("; ")}.</p>}
      <ol className="space-y-2">
        {h.hypotheses.map((x) => (
          <li key={x.id} className="rounded-md border border-ink-700 p-2">
            <div className="flex items-center gap-3">
              <span className="w-5 text-[12px] text-ink-400">{x.rank}.</span>
              <span className="flex-1 text-[13px] font-medium">{x.title}</span>
              <span className={`text-[11px] ${TONE[x.assessment] || "text-ink-300"}`}>{x.assessment}</span>
              <span className="tabular w-12 text-right text-[12px]">{x.score > 0 ? "+" : ""}{x.score.toFixed(1)}</span>
            </div>
            <div className="ml-8 mt-1 flex h-1.5 overflow-hidden rounded bg-ink-800" aria-hidden>
              <div className={x.score >= 0 ? "bg-ok" : "bg-crit"} style={{ width: `${(Math.abs(x.score) / max) * 100}%` }} />
            </div>
            <details className="ml-8 mt-1 text-[12px]">
              <summary className="cursor-pointer text-ink-400">{x.supporting.length} supporting · {x.contradicting.length} contradicting · {x.missing.length} expected but not seen</summary>
              <p className="mt-1 text-ink-400">{x.narrative}</p>
              {x.supporting.length > 0 && <ul className="mt-1 space-y-1">{x.supporting.map((s) => (
                <li key={s.indicator} className="flex flex-wrap items-center gap-1"><span className="text-ok">+{s.weight}</span> {s.label} {s.evidence.slice(0, 4).map(chip)}</li>))}</ul>}
              {x.contradicting.length > 0 && <ul className="mt-1 space-y-1">{x.contradicting.map((s) => (
                <li key={s.indicator} className="flex flex-wrap items-center gap-1"><span className="text-crit">−{(s.weight * 1.5).toFixed(1)}</span> contradicted by: {s.label} {s.evidence.slice(0, 4).map(chip)}</li>))}</ul>}
              {x.missing.length > 0 && <div className="mt-1 text-ink-500">Expected but not seen: {x.missing.map((m) => m.label).join("; ")}{x.key_evidence_missing ? " (key evidence missing: −3)" : ""}</div>}
            </details>
          </li>
        ))}
      </ol>
      <p className="text-[11px] text-ink-500">{h.method}</p>
    </div>
  );
}
