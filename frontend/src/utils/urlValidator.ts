export interface UrlValidationSuccess {
  valid: true;
  normalizedUrl: string;
  hostname: string;
  protocol: 'https:' | 'http:';
  pathname: string;
  search: string;
  isPunycode: boolean;
  punycodeHostname?: string;
  isBareDomainInput: boolean;
}

export interface UrlValidationFailure {
  valid: false;
  reason: 'empty' | 'malformed' | 'unsupported_protocol' | 'invalid_hostname';
  message: string;
  suggestedNormalization?: string;
}

export type UrlValidationResult = UrlValidationSuccess | UrlValidationFailure;

const UNSUPPORTED_PROTOCOLS = [
  'javascript:',
  'data:',
  'file:',
  'ftp:',
  'blob:',
  'mailto:',
  'tel:',
  'ws:',
  'wss:',
  'view-source:',
];

export function validateAndNormalizeUrl(rawInput: string): UrlValidationResult {
  const trimmed = rawInput.trim();

  if (!trimmed) {
    return {
      valid: false,
      reason: 'empty',
      message: 'Please enter a website URL or domain name to begin security assessment.',
    };
  }

  // Check for dangerous or unsupported protocols
  const lower = trimmed.toLowerCase();
  for (const proto of UNSUPPORTED_PROTOCOLS) {
    if (lower.startsWith(proto)) {
      return {
        valid: false,
        reason: 'unsupported_protocol',
        message: `Unsupported protocol "${proto}". Trust Shield evaluates web endpoints using HTTP or HTTPS only.`,
      };
    }
  }

  let isBare = false;
  let candidate = trimmed;

  // If user entered no protocol (e.g., "example.com" or "example.com/login")
  if (!/^https?:\/\//i.test(trimmed)) {
    isBare = true;
    candidate = `https://${trimmed}`;
  }

  try {
    const parsed = new URL(candidate);

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return {
        valid: false,
        reason: 'unsupported_protocol',
        message: `Protocol "${parsed.protocol}" is not supported. Use https:// or http://.`,
      };
    }

    const hostname = parsed.hostname;

    // Validate hostname structure
    if (!hostname || hostname.includes(' ') || !hostname.includes('.')) {
      // If it has no dot and isn't localhost
      if (hostname !== 'localhost') {
        return {
          valid: false,
          reason: 'invalid_hostname',
          message: 'Please provide a valid domain name with an extension (e.g., domain.com).',
        };
      }
    }

    const isPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');

    return {
      valid: true,
      normalizedUrl: parsed.toString(),
      hostname: parsed.hostname,
      protocol: parsed.protocol as 'https:' | 'http:',
      pathname: parsed.pathname || '/',
      search: parsed.search || '',
      isPunycode,
      punycodeHostname: isPunycode ? hostname : undefined,
      isBareDomainInput: isBare,
    };
  } catch {
    return {
      valid: false,
      reason: 'malformed',
      message: 'The URL entered appears malformed. Please verify the syntax and retry.',
    };
  }
}

