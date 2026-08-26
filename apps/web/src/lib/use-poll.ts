import { useCallback, useEffect, useRef, useState } from "react";
import { UnauthorizedError } from "../api.js";

export interface PollState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => Promise<void>;
}

/** Fetch on mount and every intervalMs (default 15s). 401s are handled
 *  globally (login gate), so only real errors surface here. */
export function usePoll<T>(fn: () => Promise<T>, intervalMs = 15_000): PollState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const reload = useCallback(async () => {
    try {
      setData(await fnRef.current());
      setError(null);
    } catch (err) {
      if (!(err instanceof UnauthorizedError)) {
        setError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
    const timer = setInterval(() => void reload(), intervalMs);
    return () => clearInterval(timer);
  }, [reload, intervalMs]);

  return { data, error, loading, reload };
}
