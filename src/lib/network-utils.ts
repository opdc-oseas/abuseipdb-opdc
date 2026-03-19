// IP and Network Utilities

export function isValidIp(ip: string): boolean {
  if (typeof ip !== 'string') return false;
  const octets = ip.split('.');
  if (octets.length !== 4) return false;
  return octets.every(octet => {
    const num = parseInt(octet, 10);
    return !isNaN(num) && num >= 0 && num <= 255 && octet === num.toString();
  });
}

export function ipToNumber(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

export function numberToIp(num: number): string {
  return [
    (num >>> 24) & 0xFF,
    (num >>> 16) & 0xFF,
    (num >>> 8) & 0xFF,
    num & 0xFF,
  ].join('.');
}

export function incrementIp(baseIp: string, increment: number): string {
  const num = ipToNumber(baseIp);
  return numberToIp((num + increment) >>> 0);
}

export interface CIDRInfo {
  cidr: string;
  networkAddress: string;
  broadcastAddress: string;
  subnetMask: string;
  prefix: number;
  totalIps: number;
  firstUsable: string;
  lastUsable: string;
}

export function parseCIDR(cidr: string): CIDRInfo | null {
  try {
    const cidrPattern = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    if (!cidrPattern.test(cidr)) throw new Error('Formato CIDR inválido');

    const [ipAddress, prefixStr] = cidr.split('/');
    const prefix = parseInt(prefixStr, 10);

    if (prefix < 0 || prefix > 32) throw new Error('Prefixo CIDR deve estar entre 0 e 32');
    if (!isValidIp(ipAddress)) throw new Error('Endereço IP inválido');

    const ipNum = ipToNumber(ipAddress);
    const mask = prefix === 0 ? 0 : (~0 >>> (32 - prefix)) << (32 - prefix);
    const networkNum = (ipNum & mask) >>> 0;
    const broadcastNum = (networkNum | (~mask & 0xFFFFFFFF)) >>> 0;
    const totalIps = Math.pow(2, 32 - prefix);

    return {
      cidr,
      networkAddress: numberToIp(networkNum),
      broadcastAddress: numberToIp(broadcastNum),
      subnetMask: numberToIp(mask >>> 0),
      prefix,
      totalIps,
      firstUsable: prefix > 30 ? numberToIp(networkNum) : numberToIp(networkNum + 1),
      lastUsable: prefix > 30 ? numberToIp(broadcastNum) : numberToIp(broadcastNum - 1),
    };
  } catch (error) {
    console.error('Erro ao analisar CIDR:', error);
    return null;
  }
}

export function formatIpForFilename(ip: string): string {
  if (!ip) return 'desconhecido';
  return ip.replace(/\./g, '-');
}
