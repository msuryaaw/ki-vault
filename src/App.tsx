import React, { useState } from 'react';
import { VaultProvider, useVault } from './stores/VaultContext';
import { Layout, NavTab } from './components/Layout';
import { CreateVault } from './pages/CreateVault';
import { UnlockVault } from './pages/UnlockVault';
import { Dashboard } from './pages/Dashboard';
import { PlatformList } from './pages/PlatformList';
import { AccountList } from './pages/AccountList';
import { VaultStatusView } from './pages/VaultStatusView';
import { Settings } from './pages/Settings';
import { Loader2 } from 'lucide-react';

const VaultContent: React.FC<{ activeTab: NavTab; setActiveTab: (tab: NavTab) => void }> = ({
  activeTab,
  setActiveTab,
}) => {
  const { status, loading } = useVault();
  // View mode when vault is uninitialised or locked: allows toggling between 'create' and 'unlock'
  const [viewMode, setViewMode] = useState<'create' | 'unlock'>('unlock');

  if (loading && status === 'Uninitialised') {
    return (
      <div className="flex flex-col items-center justify-center space-y-3 text-muted-foreground my-auto">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
        <p className="text-xs font-mono">Connecting to KiVault core engine...</p>
      </div>
    );
  }

  // 1. Vault is Unlocked -> Render content matching activeTab
  if (status === 'Unlocked') {
    switch (activeTab) {
      case 'accounts':
        return (
          <AccountList
            favoriteOnlyMode={false}
            onNavigateToPlatforms={() => setActiveTab('platforms')}
          />
        );
      case 'favorites':
        return (
          <AccountList
            favoriteOnlyMode={true}
            onNavigateToPlatforms={() => setActiveTab('platforms')}
          />
        );
      case 'platforms':
        return <PlatformList />;
      case 'vault-details':
        return <VaultStatusView />;
      case 'settings':
        return <Settings />;
      case 'overview':
      default:
        return (
          <Dashboard
            onViewVaultStatus={() => setActiveTab('vault-details')}
            onNavigateToAccounts={() => setActiveTab('accounts')}
            onNavigateToFavorites={() => setActiveTab('favorites')}
            onNavigateToPlatforms={() => setActiveTab('platforms')}
            onAddAccountClick={() => setActiveTab('accounts')}
          />
        );
    }
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
  const [activeTab, setActiveTab] = useState<NavTab>('overview');

  return (
    <VaultProvider>
      <Layout activeTab={activeTab} onTabChange={setActiveTab}>
        <VaultContent activeTab={activeTab} setActiveTab={setActiveTab} />
      </Layout>
    </VaultProvider>
  );
}
