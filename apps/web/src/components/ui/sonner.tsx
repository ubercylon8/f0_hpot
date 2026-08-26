import { Toaster as SonnerToaster } from "sonner";

/** App-wide toast host, themed to match the console. */
export function Toaster() {
  return (
    <SonnerToaster
      position="bottom-right"
      theme="dark"
      toastOptions={{
        style: {
          background: "var(--color-overlay)",
          border: "1px solid var(--color-border)",
          color: "var(--color-foreground)",
        },
      }}
    />
  );
}
