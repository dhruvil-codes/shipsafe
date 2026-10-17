"use client";

import { Shield } from "lucide-react";

export default function Navbar() {
  return (
    <nav className="fixed top-0 inset-x-0 z-50 border-b border-(--color-border) bg-(--color-bg)/80 backdrop-blur-xl">
      <div className="max-w-5xl mx-auto px-6 h-14 flex items-center justify-between">
        <a href="#top" className="flex items-center gap-2 text-(--color-text-primary) hover:text-(--color-accent) transition-colors">
          <Shield className="w-5 h-5 text-(--color-accent)" />
          <span className="font-semibold text-sm tracking-tight">ShipSafe</span>
        </a>
        <div className="flex items-center gap-6">
          <a href="#how" className="text-xs text-(--color-text-secondary) hover:text-(--color-text-primary) transition-colors">
            How it works
          </a>
          <a href="#engines" className="text-xs text-(--color-text-secondary) hover:text-(--color-text-primary) transition-colors">
            Engines
          </a>
          <a
            href="https://github.com/dhruvil-codes/shipsafe"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-(--color-text-secondary) hover:text-(--color-text-primary) transition-colors"
          >
            GitHub
          </a>
        </div>
      </div>
    </nav>
  );
}
