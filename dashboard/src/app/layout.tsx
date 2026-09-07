import type { Metadata, Viewport } from "next";
import "./globals.css";

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#07090e",
};

export const metadata: Metadata = {
  title: "[SHIELD] Web API Security Platform — SOC Command Center | PBL6",
  description: "Real-time AI-Powered Web API Security Gateway, WAF Protection, and Threat Monitoring SOC Dashboard.",
  robots: {
    index: false,
    follow: false,
  },
  openGraph: {
    title: "[SHIELD] Web API Security Platform — SOC Command Center",
    description: "Real-time AI-Powered Web API Security Gateway & WAF Monitoring Dashboard.",
    type: "website",
  },
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
