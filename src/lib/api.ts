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

export interface AuthUser {
  id?: string | number;
  name?: string;
  email?: string;
  username?: string;
  role?: string;
}

export interface AuthCredentials {
  identifier: string;
  password: string;
}

async function parseJsonResponse(response: Response): Promise<unknown> {
  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    return null;
  }

  return response.json();
}

function resolveErrorMessage(data: unknown, fallback: string) {
  if (typeof data === 'object' && data !== null) {
    if ('error' in data && typeof data.error === 'string') return data.error;
    if ('message' in data && typeof data.message === 'string') return data.message;
  }

  return fallback;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function resolveUser(data: unknown): AuthUser | null {
  if (!isRecord(data)) return null;

  if ('user' in data && isRecord(data.user)) {
    return data.user as AuthUser;
  }

  return data as AuthUser;
}

function resolveBatchData(data: unknown, total: number): BatchResult {
  if (!isRecord(data)) {
    return { results: [], stats: { total } };
  }

  return {
    results: Array.isArray(data.results) ? (data.results as IpResult[]) : [],
    stats: isRecord(data.stats) ? (data.stats as BatchResult['stats']) : { total },
  };
}

async function apiFetch(path: string, init?: RequestInit) {
  return fetch(`${CONFIG.WORKER_URL}${path}`, {
    ...init,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers || {}),
    },
  });
}

export async function login(credentials: AuthCredentials): Promise<AuthUser> {
  const payload = {
    identifier: credentials.identifier,
    username: credentials.identifier,
    email: credentials.identifier.includes('@') ? credentials.identifier : undefined,
    password: credentials.password,
  };

  const response = await apiFetch('/auth/login', {
    method: 'POST',
    body: JSON.stringify(payload),
  });

  const data = await parseJsonResponse(response);

  if (!response.ok) {
    throw new Error(resolveErrorMessage(data, 'Falha ao autenticar usuário.'));
  }

  const user = resolveUser(data);

  if (!user) {
    throw new Error('Login realizado, mas a sessão não retornou os dados do usuário.');
  }

  return user;
}

export async function logout(): Promise<void> {
  const response = await apiFetch('/auth/logout', { method: 'POST' });

  if (!response.ok && response.status !== 401) {
    const data = await parseJsonResponse(response);
    throw new Error(resolveErrorMessage(data, 'Falha ao encerrar a sessão.'));
  }
}

export async function getCurrentUser(): Promise<AuthUser | null> {
  const response = await apiFetch('/auth/me', { method: 'GET' });

  if (response.status === 401) {
    return null;
  }

  const data = await parseJsonResponse(response);

  if (!response.ok) {
    throw new Error(resolveErrorMessage(data, 'Falha ao recuperar a sessão atual.'));
  }

  return resolveUser(data);
}

export async function checkIpBatch(ips: string[]): Promise<BatchResult> {
  try {
    const response = await apiFetch('/check-range', {
      method: 'POST',
      body: JSON.stringify({ ips }),
    });

    const data = await parseJsonResponse(response);

    if (!response.ok) {
      throw new Error(resolveErrorMessage(data, 'Erro na verificação'));
    }

    return resolveBatchData(data, ips.length);
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Erro desconhecido';
    return {
      results: ips.map(ip => ({
        ip,
        error: true,
        message: message.includes('diário')
          ? 'Limite diário atingido'
          : message.toLowerCase().includes('autentic')
            ? 'Sessão expirada. Faça login novamente.'
            : 'Erro ao processar lote',
      })),
      stats: { total: ips.length, errors: ips.length },
    };
  }
}

export async function checkApiCredits(): Promise<number | null> {
  try {
    const response = await apiFetch('/check-credits');
    const data = await parseJsonResponse(response);

    if (!response.ok) {
      throw new Error(resolveErrorMessage(data, 'Erro ao verificar créditos'));
    }

    if (isRecord(data) && typeof data.credits === 'number') {
      return data.credits;
    }

    return 0;
  } catch (error) {
    console.error('Erro ao verificar créditos:', error);
    return null;
  }
}
