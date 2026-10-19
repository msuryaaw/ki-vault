import React, { useState } from 'react';
import { VaultProvider, useVault } from './stores/VaultContext';
import { Layout } from './components/Layout';
import { CreateVault } from './pages/CreateVault';
import { UnlockVault } from './pages/UnlockVault';
import { VaultStatusView } from './pages/VaultStatusView';
import { Loader2 } from 'lucide-react';

const VaultContent: React.FC = () => {
  const { status, loading } = useVault();
  // View mode when vault is uninitialised or locked: allows toggling between 'create' and 'unlock'
  const [viewMode, setViewMode] = useState<'create' | 'unlock'>('unlock');

  if (loading && status === 'Uninitialised') {
    return (
      <div className="flex flex-col items-center justify-center space-y-3 text-muted-foreground">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <p className="text-xs font-mono">Connecting to KiVault core engine...</p>
      </div>
    );
  }

  // 1. Vault is Unlocked -> Render Vault Status screen
  if (status === 'Unlocked') {
    return <VaultStatusView />;
  }

  // 2. Vault is Locked -> Render Unlock screen (or allow creating a new vault)
  if (status === 'Locked') {
    if (viewMode === 'create') {
      return <CreateVault onSwitchToUnlock={() => setViewMode('unlock')} />;
    }
    return <UnlockVault onSwitchToCreate={() => setViewMode('create')} />;
  }

  // 3. Vault is Uninitialised -> Show create screen by default, or unlock existing from path
  if (viewMode === 'unlock') {
    return <UnlockVault onSwitchToCreate={() => setViewMode('create')} />;
  }

  return <CreateVault onSwitchToUnlock={() => setViewMode('unlock')} />;
};

export default function App() {
  return (
    <VaultProvider>
      <Layout>
        <VaultContent />
      </Layout>
    </VaultProvider>
  );
}
