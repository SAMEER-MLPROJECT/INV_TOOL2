import { useEffect, useState } from "react";
import { Timer } from "lucide-react";
import { fmtTime } from "../lib/hooks";
import type { IncidentClock } from "../lib/types";

function fmtDur(s: number) {
  const a = Math.abs(s);
  const d = Math.floor(a / 86400), h = Math.floor((a % 86400) / 3600), m = Math.floor((a % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m ${Math.floor(a % 60)}s`;
}

export function ClockBanner({ clock, incident }: { clock: IncidentClock; incident: string }) {
  const due = new Date(clock.certin_due).getTime();
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t); }, []);
  const left = Math.round((due - now) / 1000);
  const open = left > 0;
  return (
    <div role="status" className={`flex flex-wrap items-center gap-x-5 gap-y-1 rounded-lg border px-4 py-2.5 text-[12px] ${open ? "border-high/50 bg-high/10" : "border-ink-700 bg-ink-900"}`}>
      <span className="flex items-center gap-2 font-semibold text-ink-100"><Timer size={15} className={open ? "text-high" : "text-ink-400"} />
        CERT-In 6-hour clock · {incident}</span>
      <span>Detected <span className="mono">{fmtTime(clock.detected_at)}</span> <span className="text-ink-400">({clock.basis})</span></span>
      <span>Report due <span className="mono">{fmtTime(clock.certin_due)}</span></span>
      <span className={open ? "font-semibold text-high" : "text-ink-400"}>{open ? `${fmtDur(left)} left` : `deadline passed ${fmtDur(left)} ago`}</span>
      <span className="text-ink-400">DPDP 72-hour report due <span className="mono">{fmtTime(clock.dpdp_detailed_report_due)}</span>{clock.dpdp_applies ? "" : " (rule applies from 13 May 2027)"}</span>
    </div>
  );
}
