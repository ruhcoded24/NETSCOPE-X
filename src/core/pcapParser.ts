import { classifyProtocol, getPortServiceName } from './protocolClassifier';
import type { PacketRecord } from './types';

function readU16(buf: Uint8Array, offset: number, le: boolean): number {
  return le ? buf[offset] | (buf[offset + 1] << 8) : (buf[offset] << 8) | buf[offset + 1];
}

function readU32(buf: Uint8Array, offset: number, le: boolean): number {
  if (le) {
    return (
      (buf[offset] |
        (buf[offset + 1] << 8) |
        (buf[offset + 2] << 16) |
        (buf[offset + 3] << 24)) >>>
      0
    );
  }
  return (
    ((buf[offset] << 24) |
      (buf[offset + 1] << 16) |
      (buf[offset + 2] << 8) |
      buf[offset + 3]) >>>
    0
  );
}

function formatIpv4(buf: Uint8Array, offset: number): string {
  return `${buf[offset]}.${buf[offset + 1]}.${buf[offset + 2]}.${buf[offset + 3]}`;
}

function formatIpv6(buf: Uint8Array, offset: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    parts.push(((buf[offset + i] << 8) | buf[offset + i + 1]).toString(16));
  }
  return parts.join(':');
}

function parseDnsQueryName(buf: Uint8Array, offset: number, end: number): string | undefined {
  // DNS header is 12 bytes
  if (offset + 12 >= end) return undefined;
  let pos = offset + 12;
  const labels: string[] = [];
  let guard = 0;
  while (pos < end && guard < 32) {
    guard++;
    const len = buf[pos];
    if (len === 0) break;
    if ((len & 0xc0) === 0xc0) break; // pointer
    pos += 1;
    if (pos + len > end) break;
    let label = '';
    for (let i = 0; i < len; i++) {
      const ch = buf[pos + i];
      label += ch >= 32 && ch <= 126 ? String.fromCharCode(ch) : '.';
    }
    labels.push(label);
    pos += len;
  }
  return labels.length > 0 ? labels.join('.') : undefined;
}

function decodeTcpFlags(flagByte: number): string[] {
  const flags: string[] = [];
  if (flagByte & 0x01) flags.push('FIN');
  if (flagByte & 0x02) flags.push('SYN');
  if (flagByte & 0x04) flags.push('RST');
  if (flagByte & 0x08) flags.push('PSH');
  if (flagByte & 0x10) flags.push('ACK');
  if (flagByte & 0x20) flags.push('URG');
  return flags;
}

function decodePacketFrame(
  frame: Uint8Array,
  origLen: number,
  epochMs: number,
  linkType: number,
  index: number,
  interfaceName: string,
): PacketRecord {
  let l3Offset = 0;
  let etherType = 0x0800;

  if (linkType === 1 && frame.length >= 14) {
    // Ethernet II
    etherType = (frame[12] << 8) | frame[13];
    l3Offset = 14;
    if (etherType === 0x8100 && frame.length >= 18) {
      // 802.1Q VLAN
      etherType = (frame[16] << 8) | frame[17];
      l3Offset = 18;
    }
  } else if (linkType === 113 && frame.length >= 16) {
    // Linux cooked capture (SLL)
    etherType = (frame[14] << 8) | frame[15];
    l3Offset = 16;
  } else if (linkType === 0 && frame.length >= 4) {
    // BSD/Null loopback
    const family = frame[0] === 0 ? frame[3] : frame[0];
    etherType = family === 24 || family === 28 || family === 30 ? 0x86dd : 0x0800;
    l3Offset = 4;
  } else if (linkType === 101 && frame.length >= 1) {
    // Raw IP
    const ver = frame[0] >> 4;
    etherType = ver === 6 ? 0x86dd : 0x0800;
    l3Offset = 0;
  }

  let sourceIp = '0.0.0.0';
  let destinationIp = '0.0.0.0';
  let sourcePort: number | null = null;
  let destinationPort: number | null = null;
  let ttl: number | null = null;
  let ipProto: number | undefined;
  let tcpFlags: string[] = [];
  let dnsQuery: string | undefined;

  if (etherType === 0x0806 && frame.length >= l3Offset + 28) {
    // ARP
    sourceIp = formatIpv4(frame, l3Offset + 14);
    destinationIp = formatIpv4(frame, l3Offset + 24);
  } else if (etherType === 0x0800 && frame.length >= l3Offset + 20) {
    // IPv4
    const ihl = (frame[l3Offset] & 0x0f) * 4;
    ttl = frame[l3Offset + 8];
    ipProto = frame[l3Offset + 9];
    sourceIp = formatIpv4(frame, l3Offset + 12);
    destinationIp = formatIpv4(frame, l3Offset + 16);

    const l4 = l3Offset + ihl;
    if (ipProto === 6 && frame.length >= l4 + 14) {
      sourcePort = (frame[l4] << 8) | frame[l4 + 1];
      destinationPort = (frame[l4 + 2] << 8) | frame[l4 + 3];
      tcpFlags = decodeTcpFlags(frame[l4 + 13]);
    } else if (ipProto === 17 && frame.length >= l4 + 8) {
      sourcePort = (frame[l4] << 8) | frame[l4 + 1];
      destinationPort = (frame[l4 + 2] << 8) | frame[l4 + 3];
      if (sourcePort === 53 || destinationPort === 53 || sourcePort === 5353 || destinationPort === 5353) {
        dnsQuery = parseDnsQueryName(frame, l4 + 8, frame.length);
      }
    }
  } else if (etherType === 0x86dd && frame.length >= l3Offset + 40) {
    // IPv6
    ttl = frame[l3Offset + 7];
    ipProto = frame[l3Offset + 6];
    sourceIp = formatIpv6(frame, l3Offset + 8);
    destinationIp = formatIpv6(frame, l3Offset + 24);
    const l4 = l3Offset + 40;
    if (ipProto === 6 && frame.length >= l4 + 14) {
      sourcePort = (frame[l4] << 8) | frame[l4 + 1];
      destinationPort = (frame[l4 + 2] << 8) | frame[l4 + 3];
      tcpFlags = decodeTcpFlags(frame[l4 + 13]);
    } else if (ipProto === 17 && frame.length >= l4 + 8) {
      sourcePort = (frame[l4] << 8) | frame[l4 + 1];
      destinationPort = (frame[l4 + 2] << 8) | frame[l4 + 3];
      if (sourcePort === 53 || destinationPort === 53) {
        dnsQuery = parseDnsQueryName(frame, l4 + 8, frame.length);
      }
    }
  }

  const classified = classifyProtocol({
    etherType,
    ipProto,
    sourcePort,
    destinationPort,
  });

  const serviceNote =
    destinationPort !== null ? ` (${getPortServiceName(destinationPort)})` : '';
  const flagNote = tcpFlags.length > 0 ? ` [${tcpFlags.join(',')}]` : '';
  const dnsNote = dnsQuery ? ` Query: ${dnsQuery}` : '';

  return {
    id: `PCAP-${index + 1}-${epochMs}`,
    timestamp: new Date(epochMs).toISOString(),
    epochMs,
    sourceIp,
    destinationIp,
    sourcePort,
    destinationPort,
    protocol: classified.protocol,
    transportProtocol: classified.transportProtocol,
    size: origLen,
    tcpFlags,
    ttl,
    interfaceName,
    direction: 'local',
    isSimulated: false,
    summary: `${classified.protocol} ${sourceIp}${sourcePort ? `:${sourcePort}` : ''} -> ${destinationIp}${destinationPort ? `:${destinationPort}` : ''}${serviceNote}${flagNote}${dnsNote}`,
    layerStack: classified.layerStack,
    dnsQuery,
  };
}

export function parsePcapBuffer(
  bytes: Uint8Array,
  interfaceName = 'pcap-import',
  maxPackets = 5000,
): { format: 'pcap' | 'pcapng'; packets: PacketRecord[] } {
  if (bytes.length < 24) {
    throw new Error('Invalid capture file: file shorter than 24-byte header.');
  }

  const magicLE = readU32(bytes, 0, true);
  const magicBE = readU32(bytes, 0, false);

  // PCAPNG Section Header Block magic: 0x0A0D0D0A
  if (magicLE === 0x0a0d0d0a) {
    return { format: 'pcapng', packets: parsePcapng(bytes, interfaceName, maxPackets) };
  }

  let le = true;
  let nano = false;
  if (magicLE === 0xa1b2c3d4) {
    le = true;
    nano = false;
  } else if (magicBE === 0xa1b2c3d4) {
    le = false;
    nano = false;
  } else if (magicLE === 0xa1b23c4d) {
    le = true;
    nano = true;
  } else if (magicBE === 0xa1b23c4d) {
    le = false;
    nano = true;
  } else {
    throw new Error(
      `Unsupported capture signature (0x${magicLE.toString(16)}). Expected valid .pcap or .pcapng binary header.`,
    );
  }

  const linkType = readU32(bytes, 20, le);
  const packets: PacketRecord[] = [];
  let offset = 24;

  while (offset + 16 <= bytes.length && packets.length < maxPackets) {
    const tsSec = readU32(bytes, offset, le);
    const tsSub = readU32(bytes, offset + 4, le);
    const inclLen = readU32(bytes, offset + 8, le);
    const origLen = readU32(bytes, offset + 12, le);
    offset += 16;

    if (inclLen > 262144 || offset + inclLen > bytes.length) break;

    const frame = bytes.subarray(offset, offset + inclLen);
    const epochMs = tsSec * 1000 + Math.floor(tsSub / (nano ? 1_000_000 : 1_000));
    packets.push(
      decodePacketFrame(frame, origLen, epochMs, linkType, packets.length, interfaceName),
    );
    offset += inclLen;
  }

  return { format: 'pcap', packets };
}

function parsePcapng(
  bytes: Uint8Array,
  interfaceName: string,
  maxPackets: number,
): PacketRecord[] {
  const packets: PacketRecord[] = [];
  let offset = 0;
  let le = true;
  const linkTypes: number[] = [];

  while (offset + 12 <= bytes.length && packets.length < maxPackets) {
    const blockType = readU32(bytes, offset, true);
    if (blockType === 0x0a0d0d0a && offset + 12 <= bytes.length) {
      const bomLE = readU32(bytes, offset + 8, true);
      le = bomLE === 0x1a2b3c4d;
    }

    const totalLen = readU32(bytes, offset + 4, le);
    if (totalLen < 12 || offset + totalLen > bytes.length) break;

    if (blockType === 0x00000001 && totalLen >= 20) {
      // Interface Description Block
      const linkType = readU16(bytes, offset + 8, le);
      linkTypes.push(linkType);
    } else if (blockType === 0x00000006 && totalLen >= 32) {
      // Enhanced Packet Block
      const ifId = readU32(bytes, offset + 8, le);
      const tsHigh = readU32(bytes, offset + 12, le);
      const tsLow = readU32(bytes, offset + 16, le);
      const capLen = readU32(bytes, offset + 20, le);
      const origLen = readU32(bytes, offset + 24, le);
      const dataStart = offset + 28;
      if (dataStart + capLen <= offset + totalLen - 4) {
        const tsUnits = tsHigh * 4294967296 + tsLow;
        const epochMs = Math.floor(tsUnits / 1000);
        const linkType = linkTypes[ifId] ?? 1;
        packets.push(
          decodePacketFrame(
            bytes.subarray(dataStart, dataStart + capLen),
            origLen,
            epochMs > 1_000_000_000_000 ? epochMs : Date.now(),
            linkType,
            packets.length,
            interfaceName,
          ),
        );
      }
    }

    offset += totalLen;
  }

  return packets;
}

function ipStringToBytes(ip: string): [number, number, number, number] {
  const parts = ip.split('.').map((n) => Number(n));
  if (parts.length === 4 && parts.every((n) => !Number.isNaN(n) && n >= 0 && n <= 255)) {
    return [parts[0], parts[1], parts[2], parts[3]];
  }
  return [127, 0, 0, 1];
}

function encodeTcpFlags(flags: string[]): number {
  let b = 0;
  if (flags.includes('FIN')) b |= 0x01;
  if (flags.includes('SYN')) b |= 0x02;
  if (flags.includes('RST')) b |= 0x04;
  if (flags.includes('PSH')) b |= 0x08;
  if (flags.includes('ACK')) b |= 0x10;
  if (flags.includes('URG')) b |= 0x20;
  return b;
}

/**
 * Serializes PacketRecords into a standards-compliant libpcap (LinkType 1 Ethernet) binary buffer.
 * Contains only synthetic L2/L3/L4 headers (no raw application payloads or credentials).
 */
export function packetsToPcapBuffer(packets: PacketRecord[]): Uint8Array {
  const chunks: Uint8Array[] = [];

  // 24-byte libpcap global header (little-endian)
  const gh = new Uint8Array(24);
  const gview = new DataView(gh.buffer);
  gview.setUint32(0, 0xa1b2c3d4, true);
  gview.setUint16(4, 2, true); // major
  gview.setUint16(6, 4, true); // minor
  gview.setInt32(8, 0, true);
  gview.setUint32(12, 0, true);
  gview.setUint32(16, 65535, true);
  gview.setUint32(20, 1, true); // Ethernet II
  chunks.push(gh);

  for (const pkt of packets) {
    const isUdp = pkt.transportProtocol === 'UDP' || pkt.protocol === 'DNS' || pkt.protocol === 'DHCP';
    const isIcmp = pkt.protocol === 'ICMP';
    const l4Len = isUdp ? 8 : isIcmp ? 8 : 20;
    const ipLen = 20 + l4Len;
    const frameLen = 14 + ipLen;
    const rec = new Uint8Array(16 + frameLen);
    const rv = new DataView(rec.buffer);

    const tsSec = Math.floor(pkt.epochMs / 1000);
    const tsUsec = (pkt.epochMs % 1000) * 1000;
    rv.setUint32(0, tsSec, true);
    rv.setUint32(4, tsUsec, true);
    rv.setUint32(8, frameLen, true);
    rv.setUint32(12, Math.max(frameLen, pkt.size), true);

    const frame = rec.subarray(16);
    // Ethernet II header (EtherType 0x0800)
    frame[12] = 0x08;
    frame[13] = 0x00;

    // IPv4 header
    const ipOff = 14;
    frame[ipOff] = 0x45;
    rv.setUint16(16 + ipOff + 2, ipLen, false);
    frame[ipOff + 8] = pkt.ttl ?? 64;
    frame[ipOff + 9] = isUdp ? 17 : isIcmp ? 1 : 6;
    const srcBytes = ipStringToBytes(pkt.sourceIp);
    const dstBytes = ipStringToBytes(pkt.destinationIp);
    frame.set(srcBytes, ipOff + 12);
    frame.set(dstBytes, ipOff + 16);

    // L4 header
    const l4Off = ipOff + 20;
    if (!isIcmp) {
      rv.setUint16(16 + l4Off, pkt.sourcePort ?? 0, false);
      rv.setUint16(16 + l4Off + 2, pkt.destinationPort ?? 0, false);
      if (isUdp) {
        rv.setUint16(16 + l4Off + 4, 8, false);
      } else {
        frame[l4Off + 12] = 0x50; // data offset 5 (20 bytes)
        frame[l4Off + 13] = encodeTcpFlags(pkt.tcpFlags);
      }
    }

    chunks.push(rec);
  }

  const totalSize = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(totalSize);
  let pos = 0;
  for (const c of chunks) {
    out.set(c, pos);
    pos += c.length;
  }
  return out;
}

/**
 * Builds a deterministic, valid libpcap sample binary representing a multi-stage
 * reconnaissance and DNS burst trace for the PCAP Forensics Lab.
 */
export function generateSamplePcapBuffer(baseEpochMs = Date.now() - 60_000): Uint8Array {
  const samplePackets: PacketRecord[] = [];
  const scanPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080];

  // Normal baseline HTTPS & DNS
  for (let i = 0; i < 12; i++) {
    const t = baseEpochMs + i * 1200;
    samplePackets.push({
      id: `S-${i}`,
      timestamp: new Date(t).toISOString(),
      epochMs: t,
      sourceIp: '192.168.10.24',
      destinationIp: '10.0.4.15',
      sourcePort: 51000 + i,
      destinationPort: i % 3 === 0 ? 53 : 443,
      protocol: i % 3 === 0 ? 'DNS' : 'HTTPS/TLS',
      transportProtocol: i % 3 === 0 ? 'UDP' : 'TCP',
      size: i % 3 === 0 ? 84 : 640,
      tcpFlags: i % 3 === 0 ? [] : ['ACK', 'PSH'],
      ttl: 64,
      interfaceName: 'eth1',
      direction: 'outbound',
      isSimulated: false,
      summary: 'Baseline traffic',
      layerStack: ['Ethernet II', 'IP'],
    });
  }

  // Port scan trace in PCAP
  scanPorts.forEach((port, idx) => {
    const t = baseEpochMs + 18_000 + idx * 450;
    samplePackets.push({
      id: `SCAN-${idx}`,
      timestamp: new Date(t).toISOString(),
      epochMs: t,
      sourceIp: '172.16.40.99',
      destinationIp: '10.0.4.15',
      sourcePort: 44100 + idx,
      destinationPort: port,
      protocol: port === 443 ? 'HTTPS/TLS' : port === 80 || port === 8080 ? 'HTTP' : port === 53 ? 'DNS' : 'TCP',
      transportProtocol: 'TCP',
      size: 64,
      tcpFlags: ['SYN'],
      ttl: 58,
      interfaceName: 'eth1',
      direction: 'inbound',
      isSimulated: false,
      summary: 'Port probe',
      layerStack: ['Ethernet II', 'IP', 'TCP'],
    });
  });

  return packetsToPcapBuffer(samplePackets);
}
