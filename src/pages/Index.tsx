import { useAuth } from '@/context/AuthContext';
import LoginPanel from '@/components/LoginPanel';
import { Loader2, LogOut, Shield } from 'lucide-react';

const Index = () => {
  const { user, isAuthenticated, isLoading, logout } = useAuth();

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <LoginPanel />;
  }

  const displayName = user?.name || user?.username || user?.email || 'Usuário autenticado';

  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-6 px-4">
      <div className="glass-card w-full max-w-lg p-8 text-center">
        <div className="mb-4 flex justify-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-primary/30 bg-primary/10">
            <Shield className="h-6 w-6 text-primary" />
          </div>
        </div>

        <h1 className="mb-2 text-2xl font-bold text-foreground">
          Bem-vindo, {displayName}!
        </h1>

        <p className="mb-6 text-sm text-muted-foreground">
          Você está autenticado no painel AbuseIPDB.
        </p>

        <button
          onClick={logout}
          className="inline-flex items-center gap-2 rounded-lg border border-border bg-secondary px-4 py-2 text-sm font-medium text-secondary-foreground transition-colors hover:bg-muted"
        >
          <LogOut className="h-4 w-4" />
          Sair
        </button>
      </div>
    </div>
  );
};

export default Index;
