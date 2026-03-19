import { IpResult } from './api';
import { formatIpForFilename } from './network-utils';

export function exportToCSV(data: IpResult[], selectedIp: string): void {
  if (!data || !data.length) return;

  const filename = `abuseipdb_report_${formatIpForFilename(selectedIp)}.csv`;

  const csvHeaderMap: Record<string, string> = {
    ip: 'IP',
    reported: 'Status',
    countryCode: 'Localidade',
    domain: 'Dominio',
    asn: 'ASN',
    organizationWebsite: 'Website Organizacao',
    mxtoolboxLink: 'MXToolbox Link',
    generalBGPLink: 'BGP/Detalhes Link',
    message: 'Mensagem/Erro',
  };

  const keys = Object.keys(csvHeaderMap).filter(
    key => data[0].hasOwnProperty(key) || ['ip', 'reported'].includes(key)
  );
  const headers = keys.map(key => csvHeaderMap[key]);

  const csvRows: string[] = [headers.join(',')];

  for (const row of data) {
    const values = keys.map(key => {
      let value: unknown = (row as Record<string, unknown>)[key];

      if (key === 'reported') {
        value = value ? 'SIM' : 'NAO';
      } else if (key === 'asn') {
        value = typeof value === 'object' && value !== null
          ? ((value as Record<string, unknown>).asn || (value as Record<string, unknown>).organization || '')
          : value;
      } else if (key === 'organizationWebsite' && value) {
        try {
          const url = new URL(value as string);
          value = url.hostname;
        } catch { /* keep original */ }
      }

      if (typeof value === 'string') {
        value = value.replace(/"/g, '""');
        if (value.includes(',') || value.includes('\n') || value.includes('"')) {
          return `"${value}"`;
        }
      }
      return value ?? '';
    });
    csvRows.push(values.join(','));
  }

  const csvString = csvRows.join('\n');
  const blob = new Blob(['\ufeff', csvString], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(link.href);
}
