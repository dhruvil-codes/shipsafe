"use client";

import dynamic from "next/dynamic";
import { useEffect, useState } from "react";

const GradientASCII = dynamic(() => import("./react-bits/GradientASCII"), { ssr: false });

/** Decorative WebGL layer; the hero remains usable without a canvas. */
export default function HeroASCII() {
  const [reducedMotion, setReducedMotion] = useState<boolean | null>(null);

  useEffect(() => {
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setReducedMotion(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  return (
    <div className="hero-ascii" aria-hidden="true" data-motion={reducedMotion ? "paused" : "running"}>
      {reducedMotion !== null && <GradientASCII
        key={String(reducedMotion)}
        colors={["#fcfcfc", "#a5c8ff", "#317cff", "#005fcc"]}
        shape="horizon"
        lightMode
        cellSize={14}
        density={0.72}
        glyphOpacity={0.85}
        gradientOpacity={0.18}
        glow={0.12}
        depthOfField={0.2}
        flicker={0.08}
        grain={0.015}
        speed={0.4}
        flow={0.5}
        mouseInteraction
        scrambleRadius={0.12}
        clickEffect="none"
        intro={false}
        dpr={1}
        style={{}}
      />}
    </div>
  );
}
