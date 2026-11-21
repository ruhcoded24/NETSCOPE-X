import type { ProtocolName, SeverityLevel } from '../core/types';

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const idx = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const val = bytes / Math.pow(1024, idx);
  return `${val >= 100 || idx === 0 ? val.toFixed(0) : val.toFixed(1)} ${units[idx]}`;
}

export function formatBps(bytesPerSec: number): string {
  return `${formatBytes(bytesPerSec)}/s`;
}

export function formatShortTime(iso: string): string {
  if (!iso) return '--:--:--';
  return iso.slice(11, 19);
}

export function getSeverityColor(severity: SeverityLevel): {
  text: string;
  hex: string;
} {
  switch (severity) {
    case 'Critical':
      return { text: 'text-[#FF3B5C]', hex: '#FF3B5C' };
    case 'High':
      return { text: 'text-[#FF9F43]', hex: '#FF9F43' };
    case 'Medium':
      return { text: 'text-[#FF00C8]', hex: '#FF00C8' };
    case 'Low':
      return { text: 'text-[#9D00FF]', hex: '#9D00FF' };
    default:
      return { text: 'text-[#C9A4FF]', hex: '#C9A4FF' };
  }
}

export function getProtocolColor(protocol: ProtocolName): string {
  switch (protocol) {
    case 'HTTPS/TLS':
      return '#FF00C8';
    case 'DNS':
      return '#39FF88';
    case 'HTTP':
      return '#FF36E2';
    case 'TCP':
      return '#9D00FF';
    case 'UDP':
      return '#5B1BFF';
    case 'ICMP':
      return '#FF9F43';
    case 'ARP':
      return '#C9A4FF';
    case 'DHCP':
      return '#e879f9';
    default:
      return '#a78bfa';
  }
}
