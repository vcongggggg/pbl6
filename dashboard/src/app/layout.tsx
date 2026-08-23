import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PBL6 — Web API Security Platform",
  description: "Web API Security Platform & Dashboard Foundation",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="vi" className="h-full antialiased">
      <body className="min-h-full flex flex-col bg-[#09090b] text-slate-100">
        {children}
      </body>
    </html>
  );
}
