import type { ProtocolName } from './types';

export interface ProtocolClassificationInput {
  ipProto?: number; // 1=ICMP, 6=TCP, 17=UDP, 58=ICMPv6
  etherType?: number; // 0x0806=ARP, 0x0800=IPv4, 0x86DD=IPv6
  sourcePort?: number | null;
  destinationPort?: number | null;
  transport?: string;
}

const WELL_KNOWN_PORT_SERVICES: Record<number, string> = {
  20: 'FTP-DATA',
  21: 'FTP',
  22: 'SSH',
  23: 'TELNET',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP-S',
  68: 'DHCP-C',
  80: 'HTTP',
  110: 'POP3',
  123: 'NTP',
  143: 'IMAP',
  161: 'SNMP',
  443: 'HTTPS/TLS',
  445: 'SMB',
  587: 'SMTP-SUB',
  993: 'IMAPS',
  1433: 'MSSQL',
  3000: 'APP-HTTP',
  3306: 'MYSQL',
  3389: 'RDP',
  5353: 'mDNS',
  5432: 'POSTGRES',
  6379: 'REDIS',
  8080: 'HTTP-ALT',
  8443: 'HTTPS-ALT',
};

export function getPortServiceName(port: number): string {
  return WELL_KNOWN_PORT_SERVICES[port] ?? `PORT-${port}`;
}

/**
 * Classifies packet protocol honoring application-layer precedence over transport.
 * For example, UDP/53 or TCP/53 is classified as DNS, never merely UDP/TCP.
 */
export function classifyProtocol(input: ProtocolClassificationInput): {
  protocol: ProtocolName;
  transportProtocol: string;
  layerStack: string[];
} {
  if (input.etherType === 0x0806) {
    return {
      protocol: 'ARP',
      transportProtocol: 'ARP',
      layerStack: ['Ethernet II', 'ARP'],
    };
  }

  const sp = input.sourcePort ?? null;
  const dp = input.destinationPort ?? null;

  let transport = (input.transport ?? '').toUpperCase();
  if (!transport) {
    if (input.ipProto === 6) transport = 'TCP';
    else if (input.ipProto === 17) transport = 'UDP';
    else if (input.ipProto === 1 || input.ipProto === 58) transport = 'ICMP';
    else transport = 'OTHER';
  }

  if (transport === 'ICMP' || input.ipProto === 1 || input.ipProto === 58) {
    return {
      protocol: 'ICMP',
      transportProtocol: 'ICMP',
      layerStack: ['Ethernet II', 'IP', 'ICMP'],
    };
  }

  const ports = [sp, dp].filter((p): p is number => p !== null);

  if (ports.includes(53) || ports.includes(5353)) {
    return {
      protocol: 'DNS',
      transportProtocol: transport || 'UDP',
      layerStack: ['Ethernet II', 'IP', transport || 'UDP', 'DNS'],
    };
  }

  if (ports.includes(67) || ports.includes(68)) {
    return {
      protocol: 'DHCP',
      transportProtocol: 'UDP',
      layerStack: ['Ethernet II', 'IP', 'UDP', 'DHCP'],
    };
  }

  if (ports.includes(443) || ports.includes(8443)) {
    return {
      protocol: 'HTTPS/TLS',
      transportProtocol: transport || 'TCP',
      layerStack: ['Ethernet II', 'IP', transport || 'TCP', 'TLS (Encrypted Metadata Only)'],
    };
  }

  if (ports.includes(80) || ports.includes(8080) || ports.includes(3000)) {
    return {
      protocol: 'HTTP',
      transportProtocol: transport || 'TCP',
      layerStack: ['Ethernet II', 'IP', transport || 'TCP', 'HTTP'],
    };
  }

  if (transport === 'TCP') {
    return {
      protocol: 'TCP',
      transportProtocol: 'TCP',
      layerStack: ['Ethernet II', 'IP', 'TCP'],
    };
  }

  if (transport === 'UDP') {
    return {
      protocol: 'UDP',
      transportProtocol: 'UDP',
      layerStack: ['Ethernet II', 'IP', 'UDP'],
    };
  }

  return {
    protocol: 'OTHER',
    transportProtocol: transport || 'OTHER',
    layerStack: ['Ethernet II', 'IP', transport || 'OTHER'],
  };
}

/**
 * Returns true for RFC1918, loopback, link-local, or private IPv6 addresses.
 * Private IP addresses must never be sent to external geolocation services.
 */
export function isPrivateIp(ip: string): boolean {
  const clean = ip.trim().toLowerCase();
  if (!clean) return true;

  if (
    clean === '::1' ||
    clean === 'localhost' ||
    clean.startsWith('fe80:') ||
    clean.startsWith('fc') ||
    clean.startsWith('fd') ||
    clean === '::'
  ) {
    return true;
  }

  // Strip IPv4-mapped IPv6 prefix
  const v4 = clean.startsWith('::ffff:') ? clean.slice(7) : clean;
  const parts = v4.split('.');
  if (parts.length !== 4) return false;
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;

  const [a, b] = nums;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224) return true; // Multicast / reserved
  return false;
}
