import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'ksi-harness — run it in the browser',
  description:
    'A hosted demo of ksi-harness: run the real FedRAMP 20x continuous control monitor against bundled fixtures and watch it collect evidence with population reconciliation, report coverage honestly, and emit schema-valid 20x + OSCAL artifacts.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="wrap">{children}</div>
      </body>
    </html>
  );
}
