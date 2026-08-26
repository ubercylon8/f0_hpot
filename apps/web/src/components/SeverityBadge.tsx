import { Badge } from "./ui/badge.js";

export function SeverityBadge({ severity }: { severity: "low" | "medium" | "high" }) {
  return (
    <Badge variant={severity} className="font-mono uppercase">
      {severity}
    </Badge>
  );
}
