import { useState, useCallback, useRef } from 'react';
import { CONFIG, PREDEFINED_IPS, STATUS_MESSAGES } from '@/lib/config';
import { parseCIDR, incrementIp } from '@/lib/network-utils';
import { checkIpBatch, checkApiCredits, IpResult } from '@/lib/api';
import { exportToCSV } from '@/lib/csv-export';
import { Shield, Play, Square, Trash2, Download, ExternalLink, Loader2, Cloud } from 'lucide-react';

interface ScanStats {
  checked: number;
  reported: number;
  clean: number;
  errors: number;
}

export default function AbuseIPDBScanner() {
  const [selectedIp, setSelectedIp] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [statusMessage, setStatusMessage] = useState(STATUS_MESSAGES.READY);
  const [progress, setProgress] = useState(0);
  const [credits, setCredits] = useState<number | null>(null);
  const [creditsLoading, setCreditsLoading] = useState(false);
  const [results, setResults] = useState<IpResult[]>([]);
  const [stats, setStats] = useState<ScanStats>({ checked: 0, reported: 0, clean: 0, errors: 0 });
  const shouldStopRef = useRef(false);

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

  const startScan = useCallback(async () => {
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
          if (enriched.message && enriched.message.includes('diário')) {
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
  }, [isScanning, selectedIp, enrichResult]);

  const stopScan = useCallback(() => {
    shouldStopRef.current = true;
    setStatusMessage(STATUS_MESSAGES.STOPPING);
  }, []);

  const clearResults = useCallback(() => {
    setResults([]);
    setStats({ checked: 0, reported: 0, clean: 0, errors: 0 });
    setProgress(0);
    setStatusMessage(STATUS_MESSAGES.READY);
  }, []);

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
      {/* Progress bar */}
      {isScanning && (
        <div className="fixed top-0 left-0 w-full h-1 bg-secondary z-50">
          <div
            className="h-full bg-primary transition-all duration-300"
            style={{ width: `${progress}%` }}
          />
        </div>
      )}

      <div className="max-w-6xl mx-auto px-4 py-8">
        {/* Header */}
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
          <p className="text-muted-foreground mt-2">
            Verificação de blocos /24 do AS262415
          </p>
        </header>

        {/* Config Card */}
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
              disabled={isScanning}
              className="w-full px-4 py-3 rounded-lg bg-secondary border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-colors"
            >
              <option value="">-- Selecione um IP --</option>
              {PREDEFINED_IPS.map(ip => (
                <option key={ip} value={ip}>{ip}/24</option>
              ))}
            </select>
          </div>

          {/* Action buttons */}
          <div className="flex flex-wrap gap-3">
            <button
              onClick={startScan}
              disabled={isScanning || !selectedIp}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-primary text-primary-foreground font-medium hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {isScanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              Iniciar Verificação
            </button>
            <button
              onClick={stopScan}
              disabled={!isScanning}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-secondary text-secondary-foreground font-medium hover:bg-secondary/80 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <Square className="h-4 w-4" />
              Parar
            </button>
            <button
              onClick={clearResults}
              disabled={isScanning}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-secondary text-secondary-foreground font-medium hover:bg-secondary/80 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <Trash2 className="h-4 w-4" />
              Limpar
            </button>
            <button
              onClick={handleExport}
              disabled={isScanning || results.length === 0}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-secondary text-secondary-foreground font-medium hover:bg-secondary/80 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <Download className="h-4 w-4" />
              Baixar CSV
            </button>
          </div>
        </div>

        {/* Status & Stats */}
        <div className="glass-card p-4 mb-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <p className="text-sm font-medium text-primary">{statusMessage}</p>
            <div className="flex gap-6 text-sm text-muted-foreground">
              <span>Total: <strong className="text-foreground">{stats.checked}</strong></span>
              <span>Reportados: <strong className="text-destructive">{stats.reported}</strong></span>
              <span>Limpos: <strong className="text-success">{stats.clean}</strong></span>
              <span>Erros: <strong className="text-warning">{stats.errors}</strong></span>
              <span>Créditos: <strong className="text-foreground">
                {creditsLoading ? 'Verificando...' : credits !== null ? credits : 'N/A'}
              </strong></span>
            </div>
          </div>
        </div>

        {/* Results Table */}
        <div className="glass-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="bg-secondary/50">
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">IP</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Status</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">ASN</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Website</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Mxtoolbox</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Link</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/50">
                {results.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-4 py-12 text-center text-muted-foreground">
                      <Shield className="h-12 w-12 mx-auto mb-3 opacity-20" />
                      <p>Nenhum resultado ainda. Selecione um IP e inicie a verificação.</p>
                    </td>
                  </tr>
                )}
                {results.map((result, i) => (
                  <tr key={`${result.ip}-${i}`} className="hover:bg-secondary/30 transition-colors">
                    <td className="px-4 py-3 font-mono text-sm text-foreground">{result.ip}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        result.error
                          ? 'bg-warning/20 text-warning'
                          : result.reported
                            ? 'bg-destructive/20 text-destructive'
                            : 'bg-success/20 text-success'
                      }`}>
                        {result.error ? 'Erro' : result.reported ? 'Reportado' : 'Limpo'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {result.asnLink ? (
                        <a href={result.asnLink} target="_blank" rel="noopener noreferrer"
                          className="text-primary hover:text-primary/80 transition-colors">
                          {getAsnText(result.asn)}
                        </a>
                      ) : getAsnText(result.asn)}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {result.organizationWebsite ? (
                        <a href={result.organizationWebsite} target="_blank" rel="noopener noreferrer"
                          className="text-primary hover:text-primary/80 transition-colors">
                          {getWebsiteHostname(result.organizationWebsite)}
                        </a>
                      ) : <span className="text-muted-foreground">N/A</span>}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {result.mxtoolboxLink ? (
                        <a href={result.mxtoolboxLink} target="_blank" rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-primary hover:text-primary/80 transition-colors">
                          Ver Check <ExternalLink className="h-3 w-3" />
                        </a>
                      ) : <span className="text-muted-foreground">N/A</span>}
                    </td>
                    <td className="px-4 py-3 text-sm">
                      {result.generalBGPLink ? (
                        <a href={result.generalBGPLink} target="_blank" rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-primary hover:text-primary/80 transition-colors">
                          Detalhes <ExternalLink className="h-3 w-3" />
                        </a>
                      ) : <span className="text-muted-foreground">N/A</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Footer */}
        <footer className="mt-8 pt-6 border-t border-border text-center text-sm text-muted-foreground">
          © {new Date().getFullYear()} OPEN Datacenter. Todos os direitos reservados.
        </footer>
      </div>
    </div>
  );
}
