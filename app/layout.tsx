import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Urban OS Runtime Federation",
  description: "Federated runtime control and collapse prevention console.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
