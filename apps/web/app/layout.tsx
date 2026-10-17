import "../styles/globals.css";
import "../styles/product.css";
import "../styles/polish.css";
import "../styles/inline-scan.css";
import MotionEffects from "@/components/MotionEffects";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: { default: "ShipSafe — Ship fast. Know what's exposed.", template: "%s · ShipSafe" },
  description: "Security testing for SaaS developers. Scan your app, understand the evidence, and verify your fixes.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <MotionEffects />
        {children}
      </body>
    </html>
  );
}
