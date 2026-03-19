import { CONFIG } from './config';

export interface IpResult {
  ip: string;
  error?: boolean;
  message?: string;
  reported?: boolean;
  countryCode?: string;
  domain?: string;
  asn?: { asn?: string | number; organization?: string; organizationWebsite?: string } | string | number;
  asnLink?: string;
  organizationWebsite?: string | null;
  mxtoolboxLink?: string;
  generalBGPLink?: string;
  totalReports?: number;
  abuseConfidenceScore?: number;
}

export interface BatchResult {
  results: IpResult[];
  stats: { total: number; errors?: number };
}

export async function checkIpBatch(ips: string[]): Promise<BatchResult> {
  try {
    const response = await fetch(`${CONFIG.WORKER_URL}/check-range`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ips }),
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || 'Erro na verificação');
    }

    const { results, stats } = await response.json();
    return {
      results: results || [],
      stats: stats || { total: ips.length },
    };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Erro desconhecido';
    return {
      results: ips.map(ip => ({
        ip,
        error: true,
        message: message.includes('diário') ? 'Limite diário atingido' : 'Erro ao processar lote',
      })),
      stats: { total: ips.length, errors: ips.length },
    };
  }
}

export async function checkApiCredits(): Promise<number | null> {
  try {
    const response = await fetch(`${CONFIG.WORKER_URL}/check-credits`);
    if (!response.ok) throw new Error('Erro ao verificar créditos');
    const data = await response.json();
    return data.credits || 0;
  } catch (error) {
    console.error('Erro ao verificar créditos:', error);
    return null;
  }
}
