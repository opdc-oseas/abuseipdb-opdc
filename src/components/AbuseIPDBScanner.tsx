import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { CONFIG, PREDEFINED_IPS, STATUS_MESSAGES } from '@/lib/config';
import { parseCIDR, incrementIp } from '@/lib/network-utils';
import { checkIpBatch, checkApiCredits, IpResult } from '@/lib/api';
import { exportToCSV } from '@/lib/csv-export';
import { useAuth } from '@/context/AuthContext';
import {
  Shield,
  Play,
  Square,
  Trash2,
  Download,
  ExternalLink,
  Loader2,
  Cloud,
  Lock,
  LogOut,
  Activity,
  ShieldCheck,
  Search,
} from 'lucide-react';

interface ScanStats {
  checked: number;
  reported: number;
  clean: number;
  errors: number;
}

export default function AbuseIPDBScanner() {
  const { user, isAuthenticated, isLoading, login, logout } = useAuth();
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);
  const [authSubmitting, setAuthSubmitting] = useState(false);
  const [selectedIp, setSelectedIp] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string>(STATUS_MESSAGES.READY);
  const [progress, setProgress] = useState(0);
  const [credits, setCredits] = useState<number | null>(null);
  const [creditsLoading, setCreditsLoading] = useState(false);
  const [results, setResults] = useState<IpResult[]>([]);
  const [stats, setStats] = useState<ScanStats>({ checked: 0, reported: 0, clean: 0, errors: 0 });
  const shouldStopRef = useRef(false);

  const displayName = useMemo(() => user?.name || user?.username || user?.email || 'Usuário autenticado', [user]);

  useEffect(() => {
    if (!isAuthenticated) {
      setCredits(null);
      setSelectedIp('');
      setResults([]);
      setStats({ checked: 0, reported: 0, clean: 0, errors: 0 });
      setProgress(0);
      setStatusMessage('Faça login para liberar a consulta.');
      return;
    }

    let ignore = false;

    const loadCredits = async () => {
      setCreditsLoading(true);
      const currentCredits = await checkApiCredits();
      if (!ignore) {
        setCredits(currentCredits);
        setCreditsLoading(false);
      }
    };

    setStatusMessage(STATUS_MESSAGES.READY);
    void loadCredits();

    return () => {
      ignore = true;
    };
  }, [isAuthenticated]);

  const enrichResult = useCallback((result: IpResult): IpResult => {
    result.asnLink = `https://bgp.he.net/ip/${result.ip}`;
    if (result.asn && typeof result.asn === 'object' && result.asn.organizationWebsite) {
      result.organizationWebsite = result.asn.organizationWebsite;
    } else if (result.domain && result.domain !== 'N/A') {
      result.organizationWebsite = `https://${result.domain}`;
    } else {
      result.organizationWebsite = null;
    }
    result.mxtoolboxLink = `https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a${result.ip}&run=toolpage`;
    if (result.asn && typeof result.asn === 'object' && result.asn.asn) {
      result.generalBGPLink = `https://bgp.he.net/AS${result.asn.asn}#_whois`;
    } else {
      result.generalBGPLink = `https://www.abuseipdb.com/check/${result.ip}`;
    }
    return result;
  }, []);

  const handleLogin = useCallback(async (event: FormEvent) => {
    event.preventDefault();

    if (!identifier || !password) {
      setAuthError('Informe seu usuário ou e-mail e a senha.');
      return;
    }

    setAuthSubmitting(true);
    setAuthError(null);

    try {
      await login({ identifier, password });
      setPassword('');
      setStatusMessage(STATUS_MESSAGES.READY);
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : 'Falha ao autenticar.');
    } finally {
      setAuthSubmitting(false);
    }
  }, [identifier, login, password]);

  const handleLogout = useCallback(async () => {
    setIsScanning(false);
    shouldStopRef.current = true;
    await logout();
  }, [logout]);

  const startScan = useCallback(async () => {
    if (!isAuthenticated) {
      setStatusMessage('Faça login para iniciar a verificação.');
      return;
    }

    if (isScanning || !selectedIp) {
      if (!selectedIp) setStatusMessage('Selecione um IP primeiro.');
      return;
    }

    const cidr = `${selectedIp}/24`;
    const cidrInfo = parseCIDR(cidr);
    if (!cidrInfo) {
      setStatusMessage('Erro: CIDR inválido para o IP selecionado.');
      return;
    }

    setCreditsLoading(true);
    const apiCredits = await checkApiCredits();
    setCreditsLoading(false);

    if (apiCredits === null) {
      setCredits(null);
      setStatusMessage('Erro ao verificar créditos da API');
      return;
    }

    setCredits(apiCredits);

    if (cidrInfo.totalIps > apiCredits) {
      setStatusMessage(`❌ Limite diário: restam ${apiCredits} consultas`);
      return;
    }

    setIsScanning(true);
    shouldStopRef.current = false;
    setResults([]);
    setStats({ checked: 0, reported: 0, clean: 0, errors: 0 });
    setProgress(0);

    let currentIndex = 0;
    let limitReached = false;
    const allResults: IpResult[] = [];
    const currentStats: ScanStats = { checked: 0, reported: 0, clean: 0, errors: 0 };

    while (currentIndex < cidrInfo.totalIps && !shouldStopRef.current && !limitReached) {
      const remaining = cidrInfo.totalIps - currentIndex;
      const batchSize = Math.min(remaining, CONFIG.BATCH_SIZE);
      const batchIps: string[] = [];

      for (let i = 0; i < batchSize; i++) {
        batchIps.push(incrementIp(cidrInfo.networkAddress, currentIndex + i));
      }

      const currentProcessed = currentIndex + batchSize;
      const percentage = Math.floor((currentProcessed / cidrInfo.totalIps) * 100);
      setProgress(percentage);
      setStatusMessage(`Verificando... ${currentProcessed}/${cidrInfo.totalIps} IPs`);

      const { results: batchResults } = await checkIpBatch(batchIps);

      for (const result of batchResults) {
        const enriched = enrichResult(result);
        currentStats.checked++;
        allResults.push(enriched);

        if (enriched.error) {
          currentStats.errors++;
          if (enriched.message && (enriched.message.includes('diário') || enriched.message.includes('Sessão expirada'))) {
            limitReached = true;
          }
        } else if (enriched.reported) {
          currentStats.reported++;
        } else {
          currentStats.clean++;
        }
      }

      setResults([...allResults]);
      setStats({ ...currentStats });
      currentIndex += batchSize;

      if (currentIndex < cidrInfo.totalIps && !shouldStopRef.current && !limitReached) {
        await new Promise(r => setTimeout(r, CONFIG.BATCH_DELAY));
      }
    }

    setIsScanning(false);
    setProgress(100);

    if (limitReached) {
      setStatusMessage(`${STATUS_MESSAGES.LIMIT_REACHED} (${currentStats.checked}/${cidrInfo.totalIps} IPs verificados)`);
    } else if (shouldStopRef.current) {
      setStatusMessage(`${STATUS_MESSAGES.STOPPED} (${currentStats.checked}/${cidrInfo.totalIps} IPs verificados)`);
    } else {
      setStatusMessage(`${STATUS_MESSAGES.COMPLETED} ${currentStats.reported} IPs reportados encontrados.`);
    }

    const updatedCredits = await checkApiCredits();
    if (updatedCredits !== null) setCredits(updatedCredits);
  }, [enrichResult, isAuthenticated, isScanning, selectedIp]);

  const stopScan = useCallback(() => {
    shouldStopRef.current = true;
    setStatusMessage(STATUS_MESSAGES.STOPPING);
  }, []);

  const clearResults = useCallback(() => {
    setResults([]);
    setStats({ checked: 0, reported: 0, clean: 0, errors: 0 });
    setProgress(0);
    setStatusMessage(isAuthenticated ? STATUS_MESSAGES.READY : 'Faça login para liberar a consulta.');
  }, [isAuthenticated]);

  const handleExport = useCallback(() => {
    if (results.length === 0) return;
    exportToCSV(results, selectedIp);
  }, [results, selectedIp]);

  const getAsnText = (asn: IpResult['asn']): string => {
    if (!asn) return 'N/A';
    if (typeof asn === 'object' && asn.asn) return String(asn.asn);
    if (typeof asn === 'string' || typeof asn === 'number') return String(asn);
    return 'N/A';
  };

  const getWebsiteHostname = (url: string | null | undefined): string => {
    if (!url) return 'N/A';
    try { return new URL(url).hostname; } catch { return 'Ver Site'; }
  };

  // ── LOGIN SCREEN ──
  if (!isAuthenticated) {
    return (
      <div className="flex min-h-screen items-center justify-center px-4">
        <div className="glass-card w-full max-w-md p-8">
          <div className="mb-6 flex flex-col items-center gap-3">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-primary/30 bg-primary/10">
              <Lock className="h-6 w-6 text-primary" />
            </div>
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-muted-foreground">
              <Cloud className="h-3.5 w-3.5" />
              Open Datacenter
            </div>
            <h1 className="text-2xl font-bold text-foreground">Acesso ao painel</h1>
            <p className="text-center text-sm text-muted-foreground">
              Faça login para liberar as consultas do AbuseIPDB e visualizar os recursos do painel.
            </p>
          </div>

          <form onSubmit={handleLogin} className="flex flex-col gap-4">
            <div className="flex flex-col gap-1.5">
              <label htmlFor="identifier" className="text-sm font-medium text-muted-foreground">Usuário ou e-mail</label>
              <input
                id="identifier"
                type="text"
                value={identifier}
                onChange={(e) => setIdentifier(e.target.value)}
                autoComplete="username"
                className="h-12 w-full rounded-2xl border border-border bg-secondary/30 px-4 text-foreground outline-none transition focus:border-primary"
                placeholder="Digite seu usuário"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <label htmlFor="password" className="text-sm font-medium text-muted-foreground">Senha</label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                className="h-12 w-full rounded-2xl border border-border bg-secondary/30 px-4 text-foreground outline-none transition focus:border-primary"
                placeholder="Digite sua senha"
              />
            </div>

            {authError && (
              <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                {authError}
              </div>
            )}

            <button
              type="submit"
              disabled={authSubmitting || isLoading}
              className="mt-2 flex h-12 items-center justify-center gap-2 rounded-2xl bg-primary font-medium text-primary-foreground transition-all hover:brightness-110 disabled:opacity-50"
            >
              {(authSubmitting || isLoading) && <Loader2 className="h-4 w-4 animate-spin" />}
              Entrar no painel
            </button>
          </form>
        </div>
      </div>
    );
  }

  // ── DASHBOARD ──
  return (
    <div className="relative mx-auto max-w-7xl space-y-6 p-4 md:p-8">
      {/* Progress bar */}
      {isScanning && (
        <div className="fixed left-0 top-0 z-50 h-1 w-full bg-muted">
          <div className="h-full bg-primary transition-all duration-300" style={{ width: `${progress}%` }} />
        </div>
      )}

      {/* Header */}
      <header className="panel-card p-6 md:p-8">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-muted-foreground">
          <Cloud className="h-3.5 w-3.5" />
          OPEN Datacenter
        </div>
        <div className="mt-1 flex flex-wrap items-center gap-2">
          <span className="dashboard-badge">Painel protegido por proxy</span>
          <span className="dashboard-badge">Ambiente {CONFIG.ENVIRONMENT}</span>
        </div>

        <h1 className="mt-4 text-gradient text-2xl font-bold md:text-3xl">AbuseIPDB Control Center</h1>
        <p className="mt-2 max-w-3xl text-sm text-muted-foreground">
          Acesse o painel com sua credencial corporativa para liberar a consulta de blocos /24, verificar créditos no proxy seguro e exportar os resultados operacionais do AS262415.
        </p>

        <div className="mt-4 flex flex-wrap gap-2">
          <span className="dashboard-badge"><Search className="h-3 w-3" /> Scanner</span>
          <span className="dashboard-badge">Consulta em lotes</span>
          <span className="dashboard-badge"><Shield className="h-3 w-3" /> Acesso</span>
          <span className="dashboard-badge">Sessão autenticada</span>
          <span className="dashboard-badge">Proxy</span>
          <span className="dashboard-badge font-mono text-[10px]">{CONFIG.WORKER_URL}</span>
        </div>

        <div className="mt-6 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-full border border-primary/30 bg-primary/10">
              <ShieldCheck className="h-4 w-4 text-primary" />
            </div>
            <div>
              <div className="text-xs text-muted-foreground">Sessão ativa</div>
              <div className="text-sm font-medium text-foreground">Usuário autenticado</div>
            </div>
          </div>
          <div className="text-sm text-foreground">{displayName}</div>
          <button onClick={handleLogout} className="flex items-center gap-2 rounded-lg border border-border px-3 py-1.5 text-sm text-muted-foreground transition hover:bg-secondary">
            <LogOut className="h-3.5 w-3.5" /> Sair
          </button>
        </div>

        <div className="mt-4 flex flex-wrap gap-6 text-sm">
          <div>
            <span className="text-muted-foreground">Créditos</span>
            <span className="ml-2 font-mono font-medium text-foreground">{creditsLoading ? '...' : credits ?? '--'}</span>
          </div>
          <div>
            <span className="text-muted-foreground">Status</span>
            <span className="ml-2 font-medium text-primary">Painel liberado</span>
          </div>
        </div>
      </header>

      {/* Scanner Config */}
      <section className="panel-card p-6">
        <div className="mb-1 text-xs font-semibold uppercase tracking-widest text-muted-foreground">Consulta operacional</div>
        <h2 className="text-lg font-bold text-foreground">Configuração da Consulta</h2>
        <p className="mt-1 text-sm text-muted-foreground">Scanner /24 autenticado</p>

        <div className="mt-4 space-y-4">
          <div>
            <label className="mb-1 block text-sm text-muted-foreground">Selecione um dos IPs pré-definidos para verificação de bloco /24</label>
            <select
              value={selectedIp}
              onChange={(e) => setSelectedIp(e.target.value)}
              disabled={isScanning || !isAuthenticated}
              className="h-12 w-full rounded-2xl border border-border bg-secondary/30 px-4 text-foreground focus:outline-none focus:ring-2 focus:ring-primary/40"
            >
              <option value="">-- Selecione um IP --</option>
              {PREDEFINED_IPS.map(ip => (
                <option key={ip} value={ip}>{ip}/24</option>
              ))}
            </select>
          </div>

          <div className="flex flex-wrap gap-2">
            <button
              onClick={startScan}
              disabled={isScanning || !selectedIp || !isAuthenticated}
              className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition hover:brightness-110 disabled:opacity-40"
            >
              {isScanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              Iniciar
            </button>
            <button
              onClick={stopScan}
              disabled={!isScanning}
              className="flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm text-muted-foreground transition hover:bg-secondary disabled:opacity-40"
            >
              <Square className="h-4 w-4" /> Parar
            </button>
            <button
              onClick={clearResults}
              disabled={isScanning}
              className="flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm text-muted-foreground transition hover:bg-secondary disabled:opacity-40"
            >
              <Trash2 className="h-4 w-4" /> Limpar
            </button>
            <button
              onClick={handleExport}
              disabled={results.length === 0}
              className="flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm text-muted-foreground transition hover:bg-secondary disabled:opacity-40"
            >
              <Download className="h-4 w-4" /> Exportar
            </button>
          </div>
        </div>
      </section>

      {/* Telemetry */}
      <section className="panel-card p-6">
        <div className="mb-1 text-xs font-semibold uppercase tracking-widest text-muted-foreground">Telemetria</div>
        <h2 className="text-lg font-bold text-foreground">Visão rápida</h2>

        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <div className="panel-muted p-4">
            <div className="text-xs text-muted-foreground">Status</div>
            <div className="mt-1 text-sm font-medium text-foreground">{statusMessage}</div>
          </div>
          <div className="panel-muted p-4">
            <div className="text-xs text-muted-foreground">Créditos API</div>
            <div className="mt-1 text-sm font-mono font-medium text-foreground">{creditsLoading ? '...' : credits ?? '--'}</div>
          </div>
        </div>

        <div className="mt-4">
          <div className="mb-2 text-xs text-muted-foreground">Resumo da execução</div>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <div className="panel-muted p-3 text-center">
              <div className="text-xs text-muted-foreground">Verificados</div>
              <div className="mt-1 text-xl font-bold text-foreground">{stats.checked}</div>
            </div>
            <div className="panel-muted p-3 text-center">
              <div className="text-xs text-muted-foreground">Reportados</div>
              <div className="mt-1 text-xl font-bold text-destructive">{stats.reported}</div>
            </div>
            <div className="panel-muted p-3 text-center">
              <div className="text-xs text-muted-foreground">Limpos</div>
              <div className="mt-1 text-xl font-bold text-primary">{stats.clean}</div>
            </div>
            <div className="panel-muted p-3 text-center">
              <div className="text-xs text-muted-foreground">Erros</div>
              <div className="mt-1 text-xl font-bold text-muted-foreground">{stats.errors}</div>
            </div>
          </div>
        </div>
      </section>

      {/* Results Table */}
      <section className="panel-card overflow-hidden">
        <div className="border-b border-border p-6">
          <div className="mb-1 text-xs font-semibold uppercase tracking-widest text-muted-foreground">Resultados operacionais</div>
          <h2 className="text-lg font-bold text-foreground">IPs analisados</h2>
          <p className="text-sm text-muted-foreground">{results.length} registro(s)</p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs uppercase tracking-wider text-muted-foreground">
                <th className="px-4 py-3">IP</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Reports</th>
                <th className="px-4 py-3">Score</th>
                <th className="px-4 py-3">País</th>
                <th className="px-4 py-3">ASN</th>
                <th className="px-4 py-3">Website</th>
                <th className="px-4 py-3">Links</th>
              </tr>
            </thead>
            <tbody>
              {results.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-muted-foreground">
                    Nenhum resultado ainda. Selecione um bloco e inicie a verificação.
                  </td>
                </tr>
              ) : (
                results.map((result, index) => (
                  <tr key={index} className="border-b border-border/50 transition-colors hover:bg-secondary/20">
                    <td className="px-4 py-3 font-mono text-xs">{result.ip}</td>
                    <td className="px-4 py-3">
                      {result.error ? (
                        <span className="inline-flex items-center gap-1 rounded-full border border-muted-foreground/30 bg-muted px-2 py-0.5 text-xs text-muted-foreground">
                          <Activity className="h-3 w-3" /> Erro
                        </span>
                      ) : result.reported ? (
                        <span className="inline-flex items-center gap-1 rounded-full border border-destructive/30 bg-destructive/10 px-2 py-0.5 text-xs text-destructive">
                          <Shield className="h-3 w-3" /> Reportado
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 text-xs text-primary">
                          <ShieldCheck className="h-3 w-3" /> Limpo
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs">{result.totalReports ?? '—'}</td>
                    <td className="px-4 py-3 text-xs">{result.abuseConfidenceScore ?? '—'}</td>
                    <td className="px-4 py-3 text-xs">{result.countryCode || '—'}</td>
                    <td className="px-4 py-3 text-xs">{getAsnText(result.asn)}</td>
                    <td className="px-4 py-3 text-xs">
                      {result.organizationWebsite ? (
                        <a href={result.organizationWebsite} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">
                          {getWebsiteHostname(result.organizationWebsite)}
                        </a>
                      ) : '—'}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-1">
                        {result.asnLink && (
                          <a href={result.asnLink} target="_blank" rel="noopener noreferrer" title="Ver IP no BGP HE" className="rounded p-1 text-muted-foreground transition hover:bg-secondary hover:text-foreground">
                            <ExternalLink className="h-3.5 w-3.5" />
                          </a>
                        )}
                        {result.mxtoolboxLink && (
                          <a href={result.mxtoolboxLink} target="_blank" rel="noopener noreferrer" title="Ver no MXToolbox" className="rounded p-1 text-muted-foreground transition hover:bg-secondary hover:text-foreground">
                            <Search className="h-3.5 w-3.5" />
                          </a>
                        )}
                        {result.generalBGPLink && (
                          <a href={result.generalBGPLink} target="_blank" rel="noopener noreferrer" title="Ver informações adicionais" className="rounded p-1 text-muted-foreground transition hover:bg-secondary hover:text-foreground">
                            <Activity className="h-3.5 w-3.5" />
                          </a>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
