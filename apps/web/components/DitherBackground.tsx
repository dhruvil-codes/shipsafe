"use client";

import { useEffect, useRef } from "react";
import { sampleDither } from "../lib/dither";

const CELL = 15;

/**
 * Full-bleed interactive dither field: a blueprint dot grid in page ink that
 * swells around the pointer. Canvas 2D, no dependencies. Static single render
 * when `prefers-reduced-motion` is set; pointer-events none so it never
 * intercepts input.
 */
export default function DitherBackground({ ink = "25, 23, 18" }: { ink?: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let raf = 0;
    let px = -1;
    let py = -1;
    const t0 = performance.now();
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    const draw = (t: number) => {
      const dpr = Math.min(2, window.devicePixelRatio || 1);
      const w = canvas.clientWidth;
      const h = canvas.clientHeight;
      if (canvas.width !== Math.floor(w * dpr) || canvas.height !== Math.floor(h * dpr)) {
        canvas.width = Math.floor(w * dpr);
        canvas.height = Math.floor(h * dpr);
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);
      const cols = Math.ceil(w / CELL);
      const rows = Math.ceil(h / CELL);
      for (let row = 0; row < rows; row++) {
        for (let col = 0; col < cols; col++) {
          const cx = col * CELL + CELL / 2;
          const cy = row * CELL + CELL / 2;
          const s = sampleDither(col, row, t, px, py, cx, cy, CELL);
          if (s.intensity <= 0) continue;
          const r = (CELL / 2 - 1.5) * s.intensity + 0.4;
          ctx.beginPath();
          ctx.arc(cx, cy, r, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(${ink},0.5)`;
          ctx.fill();
        }
      }
    };

    const onMove = (e: PointerEvent) => {
      const rect = canvas.getBoundingClientRect();
      px = e.clientX - rect.left;
      py = e.clientY - rect.top;
    };
    const onLeave = () => {
      px = -1;
      py = -1;
    };

    if (reduced) {
      draw(0);
    } else {
      const loop = () => {
        draw((performance.now() - t0) / 1000);
        raf = requestAnimationFrame(loop);
      };
      raf = requestAnimationFrame(loop);
    }
    window.addEventListener("pointermove", onMove, { passive: true });
    document.documentElement.addEventListener("pointerleave", onLeave);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("pointermove", onMove);
      document.documentElement.removeEventListener("pointerleave", onLeave);
    };
  }, [ink]);

  return (
    <canvas
      ref={canvasRef}
      className="ds-dither"
      aria-hidden="true"
    />
  );
}
