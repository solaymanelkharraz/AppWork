import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Mailroom — Floor Utilities",
  description: "Sanitize sent email source and generate seed contact matrices."
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
