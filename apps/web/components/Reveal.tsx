"use client";

import { useEffect, useRef, type ReactNode } from "react";

/**
 * Scroll reveal: children rise 20px with a fade the first time they enter
 * the viewport. Content is always rendered (no hidden-until-script states);
 * with `prefers-reduced-motion` everything appears immediately.
 */
export default function Reveal({ children, className }: { children: ReactNode; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      el.classList.add("ds-revealed");
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            entry.target.classList.add("ds-revealed");
            io.disconnect();
          }
        }
      },
      { threshold: 0.12 },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);

  return (
    <div ref={ref} className={`ds-reveal${className ? ` ${className}` : ""}`}>
      {children}
    </div>
  );
}
