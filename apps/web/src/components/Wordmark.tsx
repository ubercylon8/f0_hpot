import { cn } from "@/lib/utils";

/** f0_hpot wordmark with a blinking terminal cursor. */
export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={cn("font-mono font-bold tracking-tight", className)}>
      <span className="text-foreground">f0</span>
      <span className="text-accent">_hpot</span>
      <span className="ml-1 inline-block h-[0.95em] w-[0.5em] translate-y-[0.12em] animate-pulse bg-accent" />
    </span>
  );
}
