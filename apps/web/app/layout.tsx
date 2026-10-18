import "../styles/globals.css";
import "../styles/product.css";
import "../styles/polish.css";
import "../styles/inline-scan.css";
import MotionEffects from "@/components/MotionEffects";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: { default: "ShipSafe — Ship fast. Know what's exposed.", template: "%s · ShipSafe" },
  description: "Security testing for SaaS developers. Scan your app, understand the evidence, and verify your fixes.",
  icons: {
    icon: [
      { url: "/icon.svg", type: "image/svg+xml" },
      { url: "/favicon.ico", sizes: "32x32" },
    ],
    shortcut: "/favicon.ico",
    apple: "/apple-icon.png",
  },
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
