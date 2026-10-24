import { NavLink, Route, Routes } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Home from "./pages/Home";
import Learn from "./pages/Learn";
import Report from "./pages/Report";
import Settings from "./pages/Settings";

const link = ({ isActive }: { isActive: boolean }) =>
  `rounded-md px-3 py-1.5 text-sm ${isActive ? "bg-slate-800 text-cyan-300" : "text-slate-300 hover:text-cyan-300"}`;

export default function App() {
  return (
    <div className="mx-auto flex min-h-screen max-w-3xl flex-col px-4">
      <header className="flex flex-wrap items-center justify-between gap-2 py-4">
        <NavLink to="/" className="flex items-center gap-2 text-xl font-bold tracking-tight" aria-label="PhishGuard home">
          <img src="/logo-icon.png" alt="" width={36} height={36} className="h-9 w-9 rounded-lg" />
          <span>Phish<span className="text-cyan-400">Guard</span></span>
        </NavLink>
        <nav aria-label="Main" className="flex flex-wrap gap-1">
          <NavLink to="/" end className={link}>Scan</NavLink>
          <NavLink to="/dashboard" className={link}>Dashboard</NavLink>
          <NavLink to="/learn" className={link}>Learn</NavLink>
          <NavLink to="/settings" className={link}>Settings &amp; privacy</NavLink>
        </nav>
      </header>
      <div className="flex-1 pb-10">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/report/:id" element={<Report />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/learn" element={<Learn />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<p className="py-10 text-slate-400">Page not found.</p>} />
        </Routes>
      </div>
      <footer className="border-t border-slate-800 py-4 text-xs text-slate-500">
        PhishGuard gives signals, not verdicts. “No threats detected” never means “guaranteed safe.”
      </footer>
    </div>
  );
}
