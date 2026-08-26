import { NavLink, Outlet } from "react-router-dom";
import { Bell, Crosshair, LayoutDashboard, LogOut, Server, Siren } from "lucide-react";
import { getApiKey, logout } from "../../api.js";
import { cn } from "@/lib/utils";
import { Wordmark } from "../Wordmark.js";
import { Button } from "../ui/button.js";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/tokens", label: "Tokens", icon: Crosshair, end: false },
  { to: "/incidents", label: "Incidents", icon: Siren, end: false },
  { to: "/agents", label: "Agents", icon: Server, end: false },
  { to: "/channels", label: "Alert Channels", icon: Bell, end: false },
];

export function AppShell() {
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
    </div>
  );
}
