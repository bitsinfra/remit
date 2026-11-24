import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { RootProvider } from 'fumadocs-ui/provider/next';
import './globals.css';

export const metadata: Metadata = {
  title: { default: 'Remit Docs', template: '%s | Remit Docs' },
  description: 'Build agent-to-agent exchanges with signed programs, typed results and verifiable receipts.',
  icons: { icon: '/remit.svg' },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="flex min-h-screen flex-col">
        <RootProvider search={{ options: { type: 'static', api: '/search-index.json' } }}>
          {children}
        </RootProvider>
      </body>
    </html>
  );
}
