use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
  pub src: String,
  pub dst: String,
  pub proto: String,
  pub sport: u16,
  pub dport: u16,
  pub len: u32,
  pub summary: String,
}

fn u16be(b: &[u8]) -> u16 {
  ((b[0] as u16) << 8) | b[1] as u16
}

fn u32le(b: &[u8]) -> u32 {
  (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16) | ((b[3] as u32) << 24)
}

// Decode one DNS QNAME from offset 0 of a DNS section slice.
// Returns name plus bytes consumed. No compression pointer follow, lab scope.
fn dns_name(buf: &[u8]) -> Option<(String, usize)> {
  let mut labels = Vec::new();
  let mut i = 0;
  while i < buf.len() {
    let n = buf[i] as usize;
    if n == 0 {
      i += 1;
      break;
    }
    // Compression pointers start with 0xC0. Skip them honestly.
    if n & 0xC0 == 0xC0 {
      i += 2;
      break;
    }
    if n > 63 || i + 1 + n > buf.len() {
      return None;
    }
    labels.push(String::from_utf8_lossy(&buf[i + 1..i + 1 + n]).to_string());
    i += 1 + n;
    if labels.len() > 16 {
      break;
    }
  }
  if labels.is_empty() {
    return None;
  }
  Some((labels.join("."), i))
}

// Real PCAP parser. Supports DLT_EN10MB Ethernet plus raw IPv4.
// Little endian magic d4 c3 b2 a1 and big endian a1 b2 c3 d4.
pub fn parse_bytes(data: &[u8]) -> anyhow::Result<Vec<Flow>> {
  if data.len() < 24 {
    anyhow::bail!("too short for global header");
  }
  let magic_le = u32le(&data[0..4]);
  let little = if magic_le == 0xa1b2c3d4 { true } else if data[0] == 0xa1 && data[1] == 0xb2 { false } else {
    anyhow::bail!("bad magic");
  };
  let get32 = |b: &[u8]| -> u32 {
    if little {
      u32le(b)
    } else {
      ((b[0] as u32) << 24) | ((b[1] as u32) << 16) | ((b[2] as u32) << 8) | b[3] as u32
    }
  };
  let mut off = 24usize;
  let mut out = Vec::new();
  while off + 16 <= data.len() {
    let incl = get32(&data[off + 8..off + 12]) as usize;
    if off + 16 + incl > data.len() || incl == 0 {
      break;
    }
    let pkt = &data[off + 16..off + 16 + incl];
    if let Some(f) = decode_packet(pkt, incl as u32) {
      out.push(f);
    }
    off += 16 + incl;
    if out.len() > 100000 {
      break;
    }
  }
  Ok(out)
}

fn decode_packet(pkt: &[u8], len: u32) -> Option<Flow> {
  if pkt.len() < 14 {
    return None;
  }
  let ethertype = u16be(&pkt[12..14]);
  let (ip, proto_name): (&[u8], &str) = if ethertype == 0x0800 && pkt.len() >= 34 {
    (&pkt[14..], "IPv4")
  } else if pkt.len() >= 40 {
    // Try raw IPv4 without Ethernet (loopback captures)
    if pkt[0] >> 4 == 4 {
      (pkt, "IPv4-raw")
    } else {
      return None;
    }
  } else {
    return None;
  };
  let _ = proto_name;
  if ip.len() < 20 || ip[0] >> 4 != 4 {
    return None;
  }
  let ihl = ((ip[0] & 0x0f) as usize) * 4;
  if ip.len() < ihl + 4 {
    return None;
  }
  let proto = ip[9];
  let src = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
  let dst = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
  let rest = &ip[ihl..];
  match proto {
    6 => {
      if rest.len() < 4 {
        return None;
      }
      let sp = u16be(&rest[0..2]);
      let dp = u16be(&rest[2..4]);
      Some(Flow { src, dst, proto: "TCP".into(), sport: sp, dport: dp, len, summary: format!("TCP {sp} to {dp}") })
    }
    17 => {
      if rest.len() < 4 {
        return None;
      }
      let sp = u16be(&rest[0..2]);
      let dp = u16be(&rest[2..4]);
      // UDP payload starts after 8 byte header. DNS header is 12 more bytes,
      // then QNAME labels. Decode first query name when present.
      let summary = if (sp == 53 || dp == 53) && rest.len() > 8 + 12 + 2 {
        let dns = &rest[8..];
        let qd: u16 = ((dns[4] as u16) << 8) | dns[5] as u16;
        if qd >= 1 {
          match dns_name(&dns[12..]) {
            Some((name, _)) => format!("DNS query {name}"),
            None => "DNS".into(),
          }
        } else {
          "DNS".into()
        }
      } else {
        format!("UDP {sp} to {dp}")
      };
      Some(Flow { src, dst, proto: "UDP".into(), sport: sp, dport: dp, len, summary })
    }
    1 => Some(Flow { src, dst, proto: "ICMP".into(), sport: 0, dport: 0, len, summary: "ICMP".into() }),
    _ => Some(Flow { src, dst, proto: format!("IP-{proto}"), sport: 0, dport: 0, len, summary: "IP".into() }),
  }
}

pub fn parse_file(path: &std::path::Path) -> anyhow::Result<Vec<Flow>> {
  let data = std::fs::read(path)?;
  parse_bytes(&data)
}

// Build a minimal pcap with one TCP packet for tests. Real bytes, no mock parse.
pub fn build_test_pcap() -> Vec<u8> {
  let mut v = Vec::new();
  // global header LE: magic d4 c3 b2 a1, ver 2.4, zone 0, sigfigs 0, snaplen 65535, network 1
  v.extend([0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0]);
  // Ethernet 14 + IPv4 20 + TCP 20 = 54 bytes
  let mut pkt = vec![0u8; 54];
  // dst mac, src mac zeros, ethertype 0800
  pkt[12] = 0x08;
  pkt[13] = 0x00;
  // IPv4: version 4, ihl 5, proto TCP 6, src 127.0.0.1, dst 127.0.0.1
  pkt[14] = 0x45;
  pkt[23] = 6;
  pkt[26] = 127;
  pkt[27] = 0;
  pkt[28] = 0;
  pkt[29] = 1;
  pkt[30] = 127;
  pkt[31] = 0;
  pkt[32] = 0;
  pkt[33] = 1;
  // TCP sport 1234 = 04 d2, dport 80 = 00 50
  pkt[34] = 0x04;
  pkt[35] = 0xd2;
  pkt[36] = 0x00;
  pkt[37] = 0x50;
  // packet header LE: ts 0, incl 54, orig 54
  v.extend([0, 0, 0, 0, 0, 0, 0, 0, 54, 0, 0, 0, 54, 0, 0, 0]);
  v.extend(pkt);
  v
}
