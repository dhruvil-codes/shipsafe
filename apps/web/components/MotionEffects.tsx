"use client";

import { useEffect } from "react";
import { usePathname } from "next/navigation";

/** Animate each visible region once; content stays readable without JavaScript. */
export default function MotionEffects() {
  const pathname = usePathname();

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches ||
      !("IntersectionObserver" in window)) return;

    const seen = new WeakSet<Element>();
    const observer = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        entry.target.classList.add("motion-enter");
        observer.unobserve(entry.target);
      }
    }, { threshold: 0.08 });

    function observeRegions() {
      const regions = document.querySelectorAll<HTMLElement>(
        ".ora-board article, .ora-section > h2, .ora .metric, .ora .finding-card, .ora-close, .app-main .page-heading, .app-main .panel, .app-main .notice, .app-main .empty-state",
      );
      for (const region of regions) {
        if (seen.has(region)) continue;
        seen.add(region);
        // Only grid siblings stagger; forms and feedback appear immediately.
        const group = region.parentElement;
        if (group?.matches(".ora-board, .metric-trio, .finding-grid, .project-grid")) {
          const index = Array.from(group.children).indexOf(region);
          region.style.setProperty("--motion-delay", `${Math.min(index, 3) * 55}ms`);
        }
        observer.observe(region);
      }
    }

    observeRegions();
    // Resource-backed pages insert their panels after the first render.
    const mutations = new MutationObserver(observeRegions);
    mutations.observe(document.querySelector("main") ?? document.body, { childList: true, subtree: true });
    return () => { observer.disconnect(); mutations.disconnect(); };
  }, [pathname]);

  return null;
}
