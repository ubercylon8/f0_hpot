import { useEffect, useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { setUnauthorizedHandler } from "./api.js";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Toaster } from "@/components/ui/sonner";
import { AppShell } from "@/components/layout/AppShell";
import { LoginView } from "@/components/LoginView";
import { DashboardPage } from "@/pages/dashboard";
import { TokensPage } from "@/pages/tokens";
import { IncidentsPage } from "@/pages/incidents";
import { AgentsPage } from "@/pages/agents";
import { ChannelsPage } from "@/pages/channels";
import { SettingsPage } from "@/pages/settings";

export default function App() {
  const [needsAuth, setNeedsAuth] = useState(false);

  useEffect(() => {
    setUnauthorizedHandler(() => setNeedsAuth(true));
    return () => setUnauthorizedHandler(null);
  }, []);

  if (needsAuth) {
    return <LoginView onSuccess={() => setNeedsAuth(false)} />;
  }

  return (
    <BrowserRouter>
      <TooltipProvider>
        <Routes>
          <Route element={<AppShell />}>
            <Route index element={<DashboardPage />} />
            <Route path="tokens" element={<TokensPage />} />
            <Route path="incidents" element={<IncidentsPage />} />
            <Route path="agents" element={<AgentsPage />} />
            <Route path="channels" element={<ChannelsPage />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
        <Toaster />
      </TooltipProvider>
    </BrowserRouter>
  );
}
