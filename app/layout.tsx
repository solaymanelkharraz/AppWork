import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Mailroom — Template Lab",
  description: "Sanitize sent email source and reverse-engineer reusable templates."
};

export default function RootLayout({
  children
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
