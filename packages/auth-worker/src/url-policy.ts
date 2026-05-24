export function isUrlClientId(clientId: string): boolean {
  try {
    const url = new URL(clientId);
    return url.protocol === "https:" || url.protocol === "http:";
  } catch {
    return false;
  }
}

export function isPublicHttpsUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      !url.username &&
      !url.password &&
      !url.hash &&
      isUnambiguousPublicHost(url.hostname)
    );
  } catch {
    return false;
  }
}

export function isAllowedRedirectUri(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.hash || url.username || url.password) {
      return false;
    }
    if (url.protocol === "https:") {
      return isUnambiguousPublicHost(url.hostname);
    }
    if (url.protocol === "http:") {
      return isLoopbackHost(url.hostname);
    }
    return false;
  } catch {
    return false;
  }
}

export function isUnambiguousPublicHost(hostname: string): boolean {
  const host = normalizeHost(hostname);
  if (
    !host ||
    host.includes("*") ||
    host.endsWith(".") ||
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host.endsWith(".home") ||
    host.endsWith(".lan")
  ) {
    return false;
  }
  if (!host.includes(".") && !isIpv4(host) && !host.includes(":")) {
    return false;
  }
  return !isPrivateHost(host);
}

export function isPrivateHost(hostname: string): boolean {
  const host = normalizeHost(hostname);
  if (isLoopbackHost(host)) {
    return true;
  }
  const octets = parseIpv4(host);
  if (octets) {
    const [a, b] = octets;
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224
    );
  }
  if (host.includes(":")) {
    return (
      host === "::" ||
      host === "::1" ||
      host.startsWith("::ffff:") ||
      host.startsWith("64:ff9b:") ||
      host.startsWith("fe80:") ||
      host.startsWith("fc") ||
      host.startsWith("fd") ||
      host.startsWith("2001:0:") ||
      host.startsWith("2001::") ||
      host.startsWith("2001:db8:") ||
      host.startsWith("2002:")
    );
  }
  return false;
}

function isLoopbackHost(hostname: string): boolean {
  const host = normalizeHost(hostname);
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

function normalizeHost(hostname: string): string {
  return hostname.toLowerCase().replace(/^\[/, "").replace(/\]$/, "");
}

function isIpv4(host: string): boolean {
  return Boolean(parseIpv4(host));
}

function parseIpv4(host: string): [number, number, number, number] | null {
  const match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) {
    return null;
  }
  const octets = match.slice(1).map(Number);
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    return null;
  }
  return [octets[0] ?? 0, octets[1] ?? 0, octets[2] ?? 0, octets[3] ?? 0];
}
