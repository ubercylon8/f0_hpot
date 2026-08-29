import { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  Bell,
  Crosshair,
  Keyboard,
  LayoutDashboard,
  LogOut,
  Server,
  Settings,
  Siren,
} from "lucide-react";
import { getApiKey, logout } from "../../api.js";
import { cn } from "@/lib/utils";
import { Wordmark } from "../Wordmark.js";
import { Button } from "../ui/button.js";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "../ui/dialog.js";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/tokens", label: "Tokens", icon: Crosshair, end: false },
  { to: "/incidents", label: "Incidents", icon: Siren, end: false },
  { to: "/agents", label: "Agents", icon: Server, end: false },
  { to: "/channels", label: "Alert Channels", icon: Bell, end: false },
  { to: "/settings", label: "Settings", icon: Settings, end: false },
];

const SHORTCUTS = [
  { keys: "1 – 6", action: "Jump to Dashboard / Tokens / Incidents / Agents / Channels / Settings" },
  { keys: "/", action: "Focus the page search box (Tokens and Incidents pages)" },
  { keys: "?", action: "Show this help" },
  { keys: "Esc", action: "Close dialogs and drawers" },
];

export function AppShell() {
  const navigate = useNavigate();
  const [helpOpen, setHelpOpen] = useState(false);

  useEffect(() => {
    const routes: Record<string, string> = {
      "1": "/",
      "2": "/tokens",
      "3": "/incidents",
      "4": "/agents",
      "5": "/channels",
      "6": "/settings",
    };
    function onKey(e: KeyboardEvent) {
      const t = e.target as HTMLElement | null;
      if (
        t &&
        (t.tagName === "INPUT" ||
          t.tagName === "TEXTAREA" ||
          t.tagName === "SELECT" ||
          t.isContentEditable)
      ) {
        return;
      }
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      // A Radix dialog/sheet trigger is a <button>, not a <select>, so the
      // tag check above does not cover it: pressing 1-6 mid-edit navigated
      // away and unmounted the open dialog. Ignore navigation while any
      // modal layer is open (Esc still closes it).
      if (document.querySelector('[role="dialog"][data-state="open"]')) return;
      const to = routes[e.key];
      if (to) {
        void navigate(to);
        return;
      }
      if (e.key === "/") {
        const box = document.getElementById("page-search");
        if (box) {
          e.preventDefault();
          box.focus();
        }
        return;
      }
      if (e.key === "?") setHelpOpen(true);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [navigate]);

  return (
    <div className="min-h-screen">
      <aside className="fixed inset-y-0 left-0 flex w-60 flex-col border-r border-border bg-surface">
        <div className="border-b border-border px-5 py-5">
          <Wordmark className="text-xl" />
          <p className="mt-1 font-mono text-[11px] text-faint">deception platform</p>
        </div>
        <nav className="flex-1 space-y-1 overflow-y-auto p-3">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2.5 rounded-md border px-3 py-2 text-sm transition-colors",
                  isActive
                    ? "border-accent/25 bg-accent-dim text-accent"
                    : "border-transparent text-muted hover:bg-raised hover:text-foreground",
                )
              }
            >
              <Icon className="h-4 w-4" />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="space-y-2 border-t border-border p-3">
          <Button
            variant="ghost"
            size="sm"
            className="w-full justify-start"
            onClick={() => setHelpOpen(true)}
          >
            <Keyboard className="h-4 w-4" />
            shortcuts
          </Button>
          {getApiKey() && (
            <Button
              variant="ghost"
              size="sm"
              className="w-full justify-start"
              onClick={() => logout()}
            >
              <LogOut className="h-4 w-4" />
              log out
            </Button>
          )}
          <p className="px-1 font-mono text-[10px] text-faint">f0_hpot console</p>
        </div>
      </aside>
      <main className="pl-60">
        <div className="mx-auto max-w-7xl px-6 py-6">
          <Outlet />
        </div>
      </main>

      <Dialog open={helpOpen} onOpenChange={setHelpOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Keyboard shortcuts</DialogTitle>
            <DialogDescription>Active anywhere outside text inputs.</DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            {SHORTCUTS.map((s) => (
              <div key={s.keys} className="flex items-center gap-3 text-sm">
                <kbd className="w-16 shrink-0 rounded border border-border bg-raised px-1.5 py-0.5 text-center font-mono text-xs">
                  {s.keys}
                </kbd>
                <span className="text-muted">{s.action}</span>
              </div>
            ))}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
