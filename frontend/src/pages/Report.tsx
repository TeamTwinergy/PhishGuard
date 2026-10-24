import { Link, useParams } from "react-router-dom";
import ExportButtons from "../components/ExportButtons";
import ResultView from "../components/ResultView";
import { findScan } from "../store";

export default function Report() {
  const { id = "" } = useParams();
  const r = findScan(id);
  if (!r) {
    return (
      <div className="py-10 text-slate-300">
        <p>This report is no longer available. It may have expired or been cleared from this browser.</p>
        <Link to="/dashboard" className="mt-3 inline-block text-cyan-300 underline">Back to dashboard</Link>
      </div>
    );
  }
  return (
    <div className="space-y-4">
      <Link to="/dashboard" className="text-sm text-cyan-300 underline">← Back to dashboard</Link>
      <h1 className="break-all text-2xl font-bold">{r.hostname}</h1>
      <p className="text-sm text-slate-400">Scanned {new Date(r.scanned_at).toLocaleString()}</p>
      <ResultView r={r} actions={<ExportButtons r={r} />} />
    </div>
  );
}
