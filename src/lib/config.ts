// AbuseIPDB Scanner Configuration

export const CONFIG = {
  WORKER_URL: 'https://abuseipdb-opdc-proxy.subscriptions-ec7.workers.dev/',
  DAILY_LIMIT: 1000,
  BATCH_SIZE: 10,
  BATCH_DELAY: 1000,
  STORAGE_KEY: 'abuseipdb_app_data',
};

export const PREDEFINED_IPS = [
  '66.35.66.1',
  '66.35.87.1',
  '177.39.16.1',
  '177.39.17.1',
  '177.39.20.1',
  '177.39.21.1',
  '177.39.22.1',
  '177.39.23.1',
  '177.136.200.1',
  '177.136.201.1',
  '177.136.202.1',
  '177.136.203.1',
  '177.136.204.1',
  '177.136.205.1',
  '177.136.206.1',
  '177.136.207.1',
];

export const STATUS_MESSAGES = {
  READY: 'Pronto para verificar IPs.',
  SCANNING: '🔍 Verificando lote de IPs...',
  COMPLETED: '✅ Verificação concluída!',
  STOPPED: '⏹️ Verificação interrompida',
  LIMIT_REACHED: '⚠️ Limite diário atingido',
  CLEANING: '🧹 Resultados limpos',
  STOPPING: '⏸️ Interrompendo verificação...',
} as const;
