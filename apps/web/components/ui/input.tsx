"use client";

import * as React from "react";
import { cn } from "../../lib/utils";

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, ...props }, ref) => {
    return (
      <input
        type={type}
        className={cn(
          "flex h-12 w-full rounded-lg border border-(--color-border) bg-(--color-bg-card) px-4 py-2",
          "text-sm text-(--color-text-primary) font-[family-name:var(--font-sans)]",
          "placeholder:text-(--color-text-muted)",
          "focus:outline-none focus:ring-2 focus:ring-(--color-accent) focus:border-transparent",
          "disabled:cursor-not-allowed disabled:opacity-50",
          "transition-all duration-200",
          className,
        )}
        ref={ref}
        {...props}
      />
    );
  },
);
Input.displayName = "Input";

export { Input };
