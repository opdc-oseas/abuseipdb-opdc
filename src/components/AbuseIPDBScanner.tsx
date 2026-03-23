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
  BadgeCheck,
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

  const handleLogin = useCallback(async (event: FormEvent<HTMLFormElement>) => {
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

  return (
    <div className="min-h-screen">
      {isScanning && (
        <div className="fixed left-0 top-0 z-50 h-1 w-full bg-white/5">
          <div
            className="h-full rounded-full bg-gradient-to-r from-primary via-cyan-400 to-blue-300 transition-all duration-300"
            style={{ width: `${progress}%` }}
          />
        </div>
      )}

      <div className="mx-auto flex min-h-screen w-full max-w-7xl flex-col gap-6 px-4 py-6 lg:px-6 lg:py-8">
        <section className="panel-card overflow-hidden p-6 lg:p-8">
          <div className="flex flex-col gap-8 xl:flex-row xl:items-start xl:justify-between">
            <div className="max-w-3xl">
              <div className="flex flex-wrap items-center gap-3">
                <span className="dashboard-badge border-primary/20 bg-primary/10 text-blue-100">
                  <Cloud className="h-3.5 w-3.5 text-primary" />
                  OPEN Datacenter
                </span>
                <span className="dashboard-badge">
                  <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                  Painel protegido por proxy
                </span>
                <span className="dashboard-badge">
                  <Activity className="h-3.5 w-3.5 text-cyan-300" />
                  Ambiente {CONFIG.ENVIRONMENT}
                </span>
              </div>

              <h1 className="mt-6 text-4xl font-semibold tracking-tight text-gradient md:text-5xl">
                AbuseIPDB Control Center
              </h1>
              <p className="mt-4 max-w-2xl text-sm leading-7 text-muted-foreground md:text-base">
                Acesse o painel com sua credencial corporativa para liberar a consulta de blocos /24, verificar créditos no proxy seguro e exportar os resultados operacionais do AS262415.
              </p>

              <div className="mt-8 grid gap-3 sm:grid-cols-3">
                <div className="panel-muted p-4">
                  <p className="text-xs uppercase tracking-[0.22em] text-muted-foreground">Scanner</p>
                  <p className="mt-2 text-lg font-semibold text-foreground">Consulta em lotes</p>
                </div>
                <div className="panel-muted p-4">
                  <p className="text-xs uppercase tracking-[0.22em] text-muted-foreground">Acesso</p>
                  <p className="mt-2 text-lg font-semibold text-foreground">Sessão autenticada</p>
                </div>
                <div className="panel-muted p-4">
                  <p className="text-xs uppercase tracking-[0.22em] text-muted-foreground">Proxy</p>
                  <p className="mt-2 truncate text-lg font-semibold text-foreground">{CONFIG.WORKER_URL}</p>
                </div>
              </div>
            </div>

            <div className="w-full xl:max-w-md">
              {isAuthenticated ? (
                <div className="panel-muted p-5">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <span className="dashboard-badge border-emerald-500/20 bg-emerald-500/10 text-emerald-200">
                        <BadgeCheck className="h-3.5 w-3.5" />
                        Sessão ativa
                      </span>
                      <p className="mt-4 text-sm text-muted-foreground">Usuário autenticado</p>
                      <p className="mt-1 text-xl font-semibold text-foreground">{displayName}</p>
                    </div>
                    <button
                      onClick={handleLogout}
                      className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] px-4 py-2 text-sm font-medium text-foreground transition hover:bg-white/[0.08]"
                    >
                      <LogOut className="h-4 w-4" />
                      Sair
                    </button>
                  </div>

                  <div className="mt-5 grid gap-3 sm:grid-cols-2">
                    <div className="rounded-2xl border border-white/10 bg-black/10 p-4">
                      <p className="text-xs uppercase tracking-[0.22em] text-muted-foreground">Créditos</p>
                      <p className="mt-2 text-2xl font-semibold text-foreground">{creditsLoading ? '...' : credits ?? '--'}</p>
                    </div>
                    <div className="rounded-2xl border border-white/10 bg-black/10 p-4">
                      <p className="text-xs uppercase tracking-[0.22em] text-muted-foreground">Status</p>
                      <p className="mt-2 text-sm font-medium text-foreground">Painel liberado</p>
                    </div>
                  </div>
                </div>
              ) : (
                <form onSubmit={handleLogin} className="panel-muted p-5">
                  <div className="flex items-center gap-3">
                    <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-primary/15 text-primary">
                      <Lock className="h-5 w-5" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-foreground">Entrar no painel</p>
                      <p className="text-sm text-muted-foreground">Use sua credencial para desbloquear a consulta.</p>
                    </div>
                  </div>

                  <div className="mt-6 space-y-4">
                    <div>
                      <label htmlFor="identifier" className="mb-2 block text-sm text-muted-foreground">
                        Usuário ou e-mail
                      </label>
                      <input
                        id="identifier"
                        value={identifier}
                        onChange={(event) => setIdentifier(event.target.value)}
                        autoComplete="username"
                        className="h-12 w-full rounded-2xl border border-white/10 bg-black/10 px-4 text-foreground outline-none transition focus:border-primary"
                        placeholder="Digite seu usuário"
                      />
                    </div>
                    <div>
                      <label htmlFor="password" className="mb-2 block text-sm text-muted-foreground">
                        Senha
                      </label>
                      <input
                        id="password"
                        type="password"
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                        autoComplete="current-password"
                        className="h-12 w-full rounded-2xl border border-white/10 bg-black/10 px-4 text-foreground outline-none transition focus:border-primary"
                        placeholder="Digite sua senha"
                      />
                    </div>
                    {authError && <p className="text-sm text-destructive">{authError}</p>}
                    <button
                      type="submit"
                      disabled={authSubmitting || isLoading}
                      className="inline-flex h-12 w-full items-center justify-center gap-2 rounded-2xl bg-primary px-4 text-sm font-semibold text-primary-foreground transition hover:bg-primary/90 disabled:opacity-60"
                    >
                      {(authSubmitting || isLoading) && <Loader2 className="h-4 w-4 animate-spin" />}
                      Entrar no painel
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        </section>

        <section className="grid gap-6 xl:grid-cols-[1.3fr_0.7fr]">
          <div className={`panel-card relative overflow-hidden p-6 lg:p-7 ${!isAuthenticated ? 'pointer-events-none select-none opacity-45' : ''}`}>
            {!isAuthenticated && (
              <div className="absolute inset-0 z-10 flex items-center justify-center bg-[#08101d]/70 backdrop-blur-sm">
                <div className="max-w-md rounded-3xl border border-white/10 bg-[#0b1423]/95 p-6 text-center shadow-2xl">
                  <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/15 text-primary">
                    <Lock className="h-6 w-6" />
                  </div>
                  <h2 className="mt-4 text-xl font-semibold text-foreground">Painel bloqueado</h2>
                  <p className="mt-2 text-sm leading-6 text-muted-foreground">
                    Faça login na lateral para liberar a configuração da consulta, visualizar créditos e iniciar novas verificações.
                  </p>
                </div>
              </div>
            )}

            <div className="flex flex-col gap-6">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                <div>
                  <p className="text-xs uppercase tracking-[0.22em] text-muted-foreground">Consulta operacional</p>
                  <h2 className="mt-2 text-2xl font-semibold text-foreground">Configuração da Consulta</h2>
                </div>
                <span className="dashboard-badge self-start lg:self-auto">
                  <Search className="h-3.5 w-3.5 text-cyan-300" />
                  Scanner /24 autenticado
                </span>
              </div>

              <div className="grid gap-4 lg:grid-cols-[1fr_auto]">
                <div className="panel-muted p-4">
                  <label htmlFor="ipSelect" className="mb-3 block text-sm text-muted-foreground">
                    Selecione um dos IPs pré-definidos para verificação de bloco /24
                  </label>
                  <select
                    id="ipSelect"
                    value={selectedIp}
                    onChange={(e) => setSelectedIp(e.target.value)}
                    disabled={isScanning || !isAuthenticated}
                    className="h-12 w-full rounded-2xl border border-white/10 bg-black/10 px-4 text-foreground focus:outline-none focus:ring-2 focus:ring-primary/40"
                  >
                    <option value="">-- Selecione um IP --</option>
                    {PREDEFINED_IPS.map(ip => (
                      <option key={ip} value={ip}>{ip}/24</option>
                    ))}
                  </select>
                </div>

                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-2 xl:grid-cols-4">
                  <button
                    onClick={startScan}
                    disabled={isScanning || !selectedIp || !isAuthenticated}
                    className="inline-flex h-12 items-center justify-center gap-2 rounded-2xl bg-primary px-4 text-sm font-medium text-primary-foreground transition hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {isScanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                    Iniciar
                  </button>
                  <button
                    onClick={stopScan}
                    disabled={!isScanning || !isAuthenticated}
                    className="inline-flex h-12 items-center justify-center gap-2 rounded-2xl border border-white/10 bg-white/[0.03] px-4 text-sm font-medium text-foreground transition hover:bg-white/[0.08] disabled:opacity-50"
                  >
                    <Square className="h-4 w-4" />
                    Parar
                  </button>
                  <button
                    onClick={clearResults}
                    disabled={isScanning || !isAuthenticated}
                    className="inline-flex h-12 items-center justify-center gap-2 rounded-2xl border border-white/10 bg-white/[0.03] px-4 text-sm font-medium text-foreground transition hover:bg-white/[0.08] disabled:opacity-50"
                  >
                    <Trash2 className="h-4 w-4" />
                    Limpar
                  </button>
                  <button
                    onClick={handleExport}
                    disabled={isScanning || results.length === 0 || !isAuthenticated}
                    className="inline-flex h-12 items-center justify-center gap-2 rounded-2xl border border-white/10 bg-white/[0.03] px-4 text-sm font-medium text-foreground transition hover:bg-white/[0.08] disabled:opacity-50"
                  >
                    <Download className="h-4 w-4" />
                    Exportar
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div className="space-y-6">
            <div className="panel-card p-6">
              <p className="text-xs uppercase tracking-[0.22em] text-muted-foreground">Telemetria</p>
              <h2 className="mt-2 text-2xl font-semibold text-foreground">Visão rápida</h2>
              <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-1">
                <div className="panel-muted p-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">Status</p>
                  <p className="mt-2 text-sm font-medium leading-6 text-foreground">{statusMessage}</p>
                </div>
                <div className="panel-muted p-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">Créditos API</p>
                  <p className="mt-2 text-3xl font-semibold text-foreground">{creditsLoading ? '...' : credits ?? '--'}</p>
                </div>
              </div>
            </div>

            <div className="panel-card p-6">
              <p className="text-xs uppercase tracking-[0.22em] text-muted-foreground">Resumo da execução</p>
              <div className="mt-5 grid gap-3 sm:grid-cols-2">
                <div className="panel-muted p-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">Verificados</p>
                  <p className="mt-2 text-3xl font-semibold text-foreground">{stats.checked}</p>
                </div>
                <div className="panel-muted p-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">Reportados</p>
                  <p className="mt-2 text-3xl font-semibold text-destructive">{stats.reported}</p>
                </div>
                <div className="panel-muted p-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">Limpos</p>
                  <p className="mt-2 text-3xl font-semibold text-emerald-400">{stats.clean}</p>
                </div>
                <div className="panel-muted p-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">Erros</p>
                  <p className="mt-2 text-3xl font-semibold text-amber-300">{stats.errors}</p>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="panel-card overflow-hidden p-0">
          <div className="flex items-center justify-between border-b border-white/10 px-6 py-5">
            <div>
              <p className="text-xs uppercase tracking-[0.22em] text-muted-foreground">Resultados operacionais</p>
              <h2 className="mt-2 text-2xl font-semibold text-foreground">IPs analisados</h2>
            </div>
            <span className="dashboard-badge">{results.length} registro(s)</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full min-w-[960px] text-sm">
              <thead className="bg-white/[0.03]">
                <tr className="border-b border-white/10">
                  <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">IP</th>
                  <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">Status</th>
                  <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">Reports</th>
                  <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">Score</th>
                  <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">País</th>
                  <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">ASN</th>
                  <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">Website</th>
                  <th className="px-6 py-4 text-left text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">Links</th>
                </tr>
              </thead>
              <tbody>
                {results.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="px-6 py-16 text-center text-muted-foreground">
                      Nenhum resultado ainda. Selecione um bloco e inicie a verificação.
                    </td>
                  </tr>
                ) : (
                  results.map((result, index) => (
                    <tr key={`${result.ip}-${index}`} className="table-row-hover border-b border-white/5">
                      <td className="px-6 py-4 font-mono text-foreground">{result.ip}</td>
                      <td className="px-6 py-4">
                        {result.error ? (
                          <span className="inline-flex items-center rounded-full border border-destructive/20 bg-destructive/10 px-3 py-1 text-xs font-medium text-destructive">
                            Erro
                          </span>
                        ) : result.reported ? (
                          <span className="inline-flex items-center rounded-full border border-destructive/20 bg-destructive/10 px-3 py-1 text-xs font-medium text-destructive">
                            Reportado
                          </span>
                        ) : (
                          <span className="inline-flex items-center rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-400">
                            Limpo
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-4 text-foreground">{result.totalReports ?? '—'}</td>
                      <td className="px-6 py-4 text-foreground">{result.abuseConfidenceScore ?? '—'}</td>
                      <td className="px-6 py-4 text-foreground">{result.countryCode || '—'}</td>
                      <td className="px-6 py-4 text-foreground">{getAsnText(result.asn)}</td>
                      <td className="px-6 py-4 text-foreground">
                        {result.organizationWebsite ? (
                          <a
                            href={result.organizationWebsite}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="transition-colors hover:text-primary"
                          >
                            {getWebsiteHostname(result.organizationWebsite)}
                          </a>
                        ) : '—'}
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex gap-2">
                          {result.asnLink && (
                            <a
                              href={result.asnLink}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="rounded-xl border border-white/10 bg-white/[0.03] p-2 transition hover:bg-white/[0.08]"
                              title="Ver IP no BGP HE"
                            >
                              <ExternalLink className="h-4 w-4 text-muted-foreground" />
                            </a>
                          )}
                          {result.mxtoolboxLink && (
                            <a
                              href={result.mxtoolboxLink}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="rounded-xl border border-white/10 bg-white/[0.03] p-2 transition hover:bg-white/[0.08]"
                              title="Ver no MXToolbox"
                            >
                              <ExternalLink className="h-4 w-4 text-muted-foreground" />
                            </a>
                          )}
                          {result.generalBGPLink && (
                            <a
                              href={result.generalBGPLink}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="rounded-xl border border-white/10 bg-white/[0.03] p-2 transition hover:bg-white/[0.08]"
                              title="Ver informações adicionais"
                            >
                              <ExternalLink className="h-4 w-4 text-muted-foreground" />
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
    </div>
  );
}
