import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium tracking-wide whitespace-nowrap",
  {
    variants: {
      variant: {
        default: "border-border bg-raised text-muted",
        accent: "border-accent/30 bg-accent-dim text-accent",
        high: "border-danger/30 bg-danger-dim text-danger",
        medium: "border-warning/30 bg-warning-dim text-warning",
        low: "border-info/30 bg-info-dim text-info",
        outline: "border-border text-muted",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { badgeVariants };
