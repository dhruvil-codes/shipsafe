import "../styles/globals.css";
import "../styles/tokens.css";
import "../styles/landing.css";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
