import { downloadJson, downloadMarkdown } from "../exportReport";
import type { ScanResponse } from "../types";

const btn = "rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-semibold text-slate-200 hover:border-cyan-500 hover:text-cyan-300";

export default function ExportButtons({ r }: { r: ScanResponse }) {
  return (
    <>
      <button type="button" className={btn} onClick={() => downloadJson(r)}>Export JSON</button>
      <button type="button" className={btn} onClick={() => downloadMarkdown(r)}>Export Markdown</button>
    </>
  );
}
