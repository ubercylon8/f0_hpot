import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/**
 * Two-step destructive action. First click arms, second confirms; arming
 * lapses after a few seconds so a forgotten click can't be completed later
 * by accident.
 *
 * Several destructive controls in the console fired on a single click with
 * no undo — deleting an alert channel, revoking the API key you are
 * currently using, dropping an enrollment token.
 */
export function ConfirmButton({
  label,
  confirmLabel,
  onConfirm,
  disabled,
  busy,
  className,
  title,
}: {
  label: string;
  confirmLabel?: string;
  onConfirm: () => void;
  disabled?: boolean;
  busy?: boolean;
  className?: string;
  title?: string;
}) {
  const [armed, setArmed] = useState(false);

  useEffect(() => {
    if (!armed) return;
    const t = setTimeout(() => setArmed(false), 4000);
    return () => clearTimeout(t);
  }, [armed]);

  return (
    <Button
      variant={armed ? "destructive" : "ghost"}
      size="sm"
      disabled={disabled || busy}
      title={title}
      className={cn(!armed && "text-danger hover:text-danger", className)}
      onClick={() => {
        if (armed) {
          setArmed(false);
          onConfirm();
        } else {
          setArmed(true);
        }
      }}
    >
      {armed ? (confirmLabel ?? `confirm ${label}`) : label}
    </Button>
  );
}
