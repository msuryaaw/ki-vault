import { Shield, Lock, HardDrive, Terminal } from "lucide-react";

export default function App() {
  return (
    <main className="flex h-screen w-screen flex-col items-center justify-center bg-background p-6 text-foreground select-none">
      <div className="w-full max-w-md rounded-xl border border-border bg-card p-6 shadow-2xl space-y-6">
        <header className="flex items-center space-x-3 border-b border-border pb-4">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-accent text-accent-foreground">
            <Shield className="h-6 w-6 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight">KiVault</h1>
            <p className="text-xs text-muted-foreground">Local-first Credential Vault</p>
          </div>
        </header>

        <section className="space-y-3 text-sm text-muted-foreground">
          <div className="flex items-center justify-between rounded-lg border border-border bg-muted/30 px-3 py-2">
            <span className="flex items-center gap-2">
              <Lock className="h-4 w-4 text-primary" /> Status
            </span>
            <span className="rounded bg-accent px-2 py-0.5 text-xs font-semibold text-accent-foreground">
              Phase 0 & 1 Skeleton
            </span>
          </div>

          <div className="flex items-center justify-between rounded-lg border border-border bg-muted/30 px-3 py-2">
            <span className="flex items-center gap-2">
              <HardDrive className="h-4 w-4 text-primary" /> Runtime
            </span>
            <span className="text-xs text-foreground">Tauri 2 + React + TS</span>
          </div>

          <div className="flex items-center justify-between rounded-lg border border-border bg-muted/30 px-3 py-2">
            <span className="flex items-center gap-2">
              <Terminal className="h-4 w-4 text-primary" /> Core Engine
            </span>
            <span className="text-xs text-foreground">Rust (Security Authority)</span>
          </div>
        </section>

        <footer className="rounded-lg border border-border/50 bg-muted/20 p-3 text-center text-xs text-muted-foreground">
          Framework initialized. Ready for Phase 2 cryptographic core.
        </footer>
      </div>
    </main>
  );
}
