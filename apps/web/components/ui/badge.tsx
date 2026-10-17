"use client";

import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "../../lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-[11px] font-medium tracking-wider uppercase border",
  {
    variants: {
      variant: {
        default: "text-(--color-text-secondary) bg-[rgba(136,136,160,0.08)] border-[rgba(136,136,160,0.15)]",
        critical: "text-(--color-red) bg-(--color-red-muted) border-[rgba(239,68,68,0.2)]",
        high: "text-(--color-amber) bg-(--color-amber-muted) border-[rgba(245,158,11,0.2)]",
        medium: "text-[#a78bfa] bg-[rgba(167,139,250,0.12)] border-[rgba(167,139,250,0.2)]",
        low: "text-(--color-cyan) bg-[rgba(6,182,212,0.12)] border-[rgba(6,182,212,0.2)]",
        passed: "text-(--color-green) bg-(--color-green-muted) border-[rgba(34,197,94,0.2)]",
        accent: "text-(--color-accent) bg-(--color-accent-muted) border-[rgba(99,102,241,0.2)]",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

const Badge = React.forwardRef<HTMLSpanElement, BadgeProps>(
  ({ className, variant, ...props }, ref) => (
    <span ref={ref} className={cn(badgeVariants({ variant, className }))} {...props} />
  ),
);
Badge.displayName = "Badge";

export { Badge, badgeVariants };
