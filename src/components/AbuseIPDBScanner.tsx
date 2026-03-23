import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { CONFIG, PREDEFINED_IPS, STATUS_MESSAGES } from '@/lib/config';
import { parseCIDR, incrementIp } from '@/lib/network-utils';
import { checkIpBatch, checkApiCredits, IpResult } from '@/lib/api';
import { exportToCSV } from '@/lib/csv-export';
import { useAuth } from '@/context/AuthContext';
import { Shield, Play, Square, Trash2, Download, ExternalLink, Loader2, Cloud, Lock, LogOut } from 'lucide-react';

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
    <div className="min-h-screen bg-background">
      {isScanning && (
        <div className="fixed top-0 left-0 w-full h-1 bg-secondary z-50">
          <div
            className="h-full bg-primary transition-all duration-300"
            style={{ width: `${progress}%` }}
          />
        </div>
      )}

      <div className="max-w-6xl mx-auto px-4 py-8">
        <header className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-2">
            <Cloud className="h-8 w-8 text-primary" />
            <span className="text-sm font-semibold tracking-[0.3em] uppercase text-muted-foreground">
              OPEN Datacenter
            </span>
          </div>
          <h1 className="text-3xl font-bold text-foreground flex items-center justify-center gap-3">
            <Shield className="h-8 w-8 text-primary" />
            Consulta de IPs — AbuseIPDB
          </h1>
          <p className="text-muted-foreground mt-2">Verificação de blocos /24 do AS262415</p>
        </header>

        <div className="glass-card p-6 mb-6 border border-border/60 bg-card/90 backdrop-blur">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
            <div>
              <h2 className="text-lg font-semibold text-foreground mb-2 flex items-center gap-2">
                <Lock className="h-5 w-5 text-primary" />
                Controle de Acesso
              </h2>
              <p className="text-sm text-muted-foreground max-w-2xl">
                O painel abaixo só é liberado após autenticação no proxy seguro da Cloudflare. O frontend mantém apenas a sessão atual no navegador.
              </p>
            </div>

            {isAuthenticated ? (
              <div className="w-full lg:max-w-md rounded-xl border border-primary/30 bg-primary/5 p-4">
                <p className="text-sm text-muted-foreground">Sessão autenticada</p>
                <p className="text-base font-semibold text-foreground mt-1">{displayName}</p>
                <div className="mt-4 flex flex-wrap gap-3 text-sm text-muted-foreground">
                  <span className="rounded-full bg-background px-3 py-1 border border-border">Ambiente: {CONFIG.ENVIRONMENT}</span>
                  <span className="rounded-full bg-background px-3 py-1 border border-border">
                    Créditos: {creditsLoading ? '...' : credits ?? 'indisponível'}
                  </span>
                </div>
                <button
                  onClick={handleLogout}
                  className="mt-4 inline-flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm font-medium text-foreground hover:bg-secondary transition-colors"
                >
                  <LogOut className="h-4 w-4" />
                  Sair
                </button>
              </div>
            ) : (
              <form onSubmit={handleLogin} className="w-full lg:max-w-md rounded-xl border border-border bg-background p-4 space-y-4">
                <div>
                  <label htmlFor="identifier" className="block text-sm text-muted-foreground mb-2">
                    Usuário ou e-mail
                  </label>
                  <input
                    id="identifier"
                    value={identifier}
                    onChange={(event) => setIdentifier(event.target.value)}
                    autoComplete="username"
                    className="w-full rounded-lg border border-border bg-secondary px-4 py-3 text-foreground outline-none transition focus:border-primary"
                    placeholder="Digite seu usuário"
                  />
                </div>
                <div>
                  <label htmlFor="password" className="block text-sm text-muted-foreground mb-2">
                    Senha
                  </label>
                  <input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    autoComplete="current-password"
                    className="w-full rounded-lg border border-border bg-secondary px-4 py-3 text-foreground outline-none transition focus:border-primary"
                    placeholder="Digite sua senha"
                  />
                </div>
                {authError && <p className="text-sm text-destructive">{authError}</p>}
                <button
                  type="submit"
                  disabled={authSubmitting || isLoading}
                  className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-3 font-medium text-primary-foreground transition hover:bg-primary/90 disabled:opacity-60"
                >
                  {(authSubmitting || isLoading) && <Loader2 className="h-4 w-4 animate-spin" />}
                  Entrar no painel
                </button>
              </form>
            )}
          </div>
        </div>

        <div className={`relative transition-all ${!isAuthenticated ? 'pointer-events-none select-none opacity-40 blur-[1px]' : ''}`}>
          {!isAuthenticated && (
            <div className="absolute inset-0 z-10 flex items-center justify-center rounded-2xl bg-background/80 backdrop-blur-sm">
              <div className="max-w-md rounded-2xl border border-border bg-card p-6 text-center shadow-xl">
                <Lock className="mx-auto h-8 w-8 text-primary" />
                <h2 className="mt-3 text-xl font-semibold text-foreground">Autenticação obrigatória</h2>
                <p className="mt-2 text-sm text-muted-foreground">
                  Faça login acima para liberar a configuração da consulta, verificar créditos e iniciar o scanner.
                </p>
              </div>
            </div>
          )}

          <div className="glass-card p-6 mb-6">
            <h2 className="text-lg font-semibold text-foreground mb-4">Configuração da Consulta</h2>

            <div className="mb-4">
              <label htmlFor="ipSelect" className="block text-sm text-muted-foreground mb-2">
                Selecione um dos IPs pré-definidos para verificação de bloco /24
              </label>
              <select
                id="ipSelect"
                value={selectedIp}
                onChange={(e) => setSelectedIp(e.target.value)}
                disabled={isScanning || !isAuthenticated}
                className="w-full px-4 py-3 rounded-lg bg-secondary border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-colors"
              >
                <option value="">-- Selecione um IP --</option>
                {PREDEFINED_IPS.map(ip => (
                  <option key={ip} value={ip}>{ip}/24</option>
                ))}
              </select>
            </div>

            <div className="flex flex-wrap gap-3">
              <button
                onClick={startScan}
                disabled={isScanning || !selectedIp || !isAuthenticated}
                className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-primary text-primary-foreground font-medium hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {isScanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                Iniciar Verificação
              </button>
              <button
                onClick={stopScan}
                disabled={!isScanning || !isAuthenticated}
                className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-secondary text-secondary-foreground font-medium hover:bg-secondary/80 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                <Square className="h-4 w-4" />
                Parar
              </button>
              <button
                onClick={clearResults}
                disabled={isScanning || !isAuthenticated}
                className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-secondary text-secondary-foreground font-medium hover:bg-secondary/80 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                <Trash2 className="h-4 w-4" />
                Limpar
              </button>
              <button
                onClick={handleExport}
                disabled={isScanning || results.length === 0 || !isAuthenticated}
                className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-secondary text-secondary-foreground font-medium hover:bg-secondary/80 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                <Download className="h-4 w-4" />
                Baixar CSV
              </button>
            </div>
          </div>

          <div className="glass-card p-6 mb-6">
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <div className="bg-secondary/30 rounded-lg p-4">
                <p className="text-sm text-muted-foreground">Status</p>
                <p className="text-lg font-semibold text-foreground mt-1">{statusMessage}</p>
              </div>
              <div className="bg-secondary/30 rounded-lg p-4">
                <p className="text-sm text-muted-foreground">Créditos API</p>
                <p className="text-2xl font-bold text-primary mt-1">
                  {creditsLoading ? '...' : credits ?? '--'}
                </p>
              </div>
              <div className="bg-secondary/30 rounded-lg p-4">
                <p className="text-sm text-muted-foreground">Verificados</p>
                <p className="text-2xl font-bold text-foreground mt-1">{stats.checked}</p>
              </div>
              <div className="bg-secondary/30 rounded-lg p-4">
                <p className="text-sm text-muted-foreground">Reportados</p>
                <p className="text-2xl font-bold text-destructive mt-1">{stats.reported}</p>
              </div>
              <div className="bg-secondary/30 rounded-lg p-4">
                <p className="text-sm text-muted-foreground">Limpos</p>
                <p className="text-2xl font-bold text-green-500 mt-1">{stats.clean}</p>
              </div>
            </div>
          </div>

          <div className="glass-card p-6 overflow-x-auto">
            <h2 className="text-lg font-semibold text-foreground mb-4">Resultados</h2>
            <table className="w-full min-w-[900px] text-sm">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left p-3 text-muted-foreground font-medium">IP</th>
                  <th className="text-left p-3 text-muted-foreground font-medium">Status</th>
                  <th className="text-left p-3 text-muted-foreground font-medium">Reports</th>
                  <th className="text-left p-3 text-muted-foreground font-medium">Score</th>
                  <th className="text-left p-3 text-muted-foreground font-medium">País</th>
                  <th className="text-left p-3 text-muted-foreground font-medium">ASN</th>
                  <th className="text-left p-3 text-muted-foreground font-medium">Website</th>
                  <th className="text-left p-3 text-muted-foreground font-medium">Links</th>
                </tr>
              </thead>
              <tbody>
                {results.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="text-center p-8 text-muted-foreground">
                      Nenhum resultado ainda. Selecione um bloco e inicie a verificação.
                    </td>
                  </tr>
                ) : (
                  results.map((result, index) => (
                    <tr key={`${result.ip}-${index}`} className="border-b border-border/50 hover:bg-secondary/20 transition-colors">
                      <td className="p-3 font-mono text-foreground">{result.ip}</td>
                      <td className="p-3">
                        {result.error ? (
                          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-destructive/10 text-destructive">
                            Erro
                          </span>
                        ) : result.reported ? (
                          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-destructive/10 text-destructive">
                            Reportado
                          </span>
                        ) : (
                          <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-500/10 text-green-500">
                            Limpo
                          </span>
                        )}
                      </td>
                      <td className="p-3 text-foreground">{result.totalReports ?? '—'}</td>
                      <td className="p-3 text-foreground">{result.abuseConfidenceScore ?? '—'}</td>
                      <td className="p-3 text-foreground">{result.countryCode || '—'}</td>
                      <td className="p-3 text-foreground">{getAsnText(result.asn)}</td>
                      <td className="p-3 text-foreground">
                        {result.organizationWebsite ? (
                          <a
                            href={result.organizationWebsite}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="hover:text-primary transition-colors"
                          >
                            {getWebsiteHostname(result.organizationWebsite)}
                          </a>
                        ) : '—'}
                      </td>
                      <td className="p-3">
                        <div className="flex gap-2">
                          {result.asnLink && (
                            <a
                              href={result.asnLink}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="p-1.5 rounded-md hover:bg-secondary transition-colors"
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
                              className="p-1.5 rounded-md hover:bg-secondary transition-colors"
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
                              className="p-1.5 rounded-md hover:bg-secondary transition-colors"
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
        </div>
      </div>
    </div>
  );
}
