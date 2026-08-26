import { useState } from "react";
import { login, setApiKey } from "../api.js";
import { Wordmark } from "./Wordmark.js";
import { Button } from "./ui/button.js";
import { Card, CardContent, CardDescription, CardHeader } from "./ui/card.js";
import { Input } from "./ui/input.js";

export function LoginView({ onSuccess }: { onSuccess: () => void }) {
  const [key, setKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await login(key.trim());
      setApiKey(key.trim());
      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-sm">
        <CardHeader className="gap-3 p-6">
          <Wordmark className="text-2xl" />
          <CardDescription>
            This console requires an API key. Create one with{" "}
            <code className="font-mono text-foreground">POST /api/v1/auth/keys</code>{" "}
            or use the admin token (
            <code className="font-mono text-foreground">F0_ADMIN_TOKEN</code>).
          </CardDescription>
        </CardHeader>
        <CardContent className="p-6 pt-0">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void submit();
            }}
            className="space-y-4"
          >
            <Input
              type="password"
              autoFocus
              placeholder="API key"
              value={key}
              onChange={(e) => setKey(e.target.value)}
            />
            {error && <p className="text-sm text-danger">{error}</p>}
            <Button type="submit" disabled={busy || !key.trim()} className="w-full">
              {busy ? "checking…" : "log in"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
