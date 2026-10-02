import { URLFeatureVector, FeatureDetail, FeatureKey } from '../types';

// List of recognized URL shortening domains
const SHORTENER_DOMAINS = new Set([
  'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'is.gd', 'buff.ly',
  'adf.ly', 'bit.do', 'cutt.ly', 'rb.gy', 'rebrandly.com', 'shorte.st',
  'tiny.cc', 'bc.vc', 'qr.ae', 'snipurl.com', 'clck.ru', 'v.gd', 'shorturl.at'
]);

// High-risk or suspicious Top-Level Domains frequently utilized in phishing campaigns
const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'work', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'club',
  'loan', 'site', 'bid', 'click', 'racing', 'download', 'stream', 'trade',
  'zip', 'mov', 'support', 'rest', 'guru', 'link', 'icu', 'monster', 'hair', 'beauty'
]);

// Sensitive keywords associated with credential harvesting and phishing lures
const SENSITIVE_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification', 'update',
  'banking', 'bank', 'secure', 'security', 'account', 'wallet', 'recover',
  'password', 'passcode', 'authenticate', 'webscr', 'confirm', 'billing',
  'auth', 'suspended', 'alert', 'validate', 'portal', 'ebayisapi', 'paypal',
  'appleid', 'microsoft-online', 'netflix-verify', 'wellsfargo'
];

// Target brands commonly spoofed
const TARGET_BRANDS = [
  { name: 'PayPal', tokens: ['paypal', 'pay-pal', 'paypa1'] },
  { name: 'Apple', tokens: ['appleid', 'apple-id', 'icloud-verify', 'apple-support'] },
  { name: 'Microsoft / Office 365', tokens: ['microsoft', 'office365', 'outlook-login', 'ms-online'] },
  { name: 'Google / Gmail', tokens: ['accounts-google', 'gmail-verify', 'google-security', 'g-suite'] },
  { name: 'Chase Bank', tokens: ['chase-online', 'chase-security', 'chasebank'] },
  { name: 'Amazon', tokens: ['amazon-security', 'amazon-update', 'amz-order'] },
  { name: 'Netflix', tokens: ['netflix-update', 'netflix-verify', 'nflx-billing'] },
  { name: 'Bank of America', tokens: ['bankofamerica-verify', 'bofa-online', 'bofa-auth'] },
  { name: 'Meta / Facebook', tokens: ['facebook-security', 'meta-support', 'fb-verify'] }
];

/**
 * Calculates the Shannon Entropy of a string to detect randomness / obfuscation
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const frequencies: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

/**
 * Validates and normalizes submitted URL
 */
export function normalizeAndValidateUrl(rawUrl: string): {
  isValid: boolean;
  canonicalUrl: string;
  parsedUrl: URL | null;
  error?: string;
} {
  let cleaned = rawUrl.trim();
  if (!cleaned) {
    return { isValid: false, canonicalUrl: '', parsedUrl: null, error: 'URL input cannot be empty' };
  }

  // If no scheme provided, prepend http:// for URL parser parsing
  if (!/^https?:\/\//i.test(cleaned)) {
    cleaned = 'http://' + cleaned;
  }

  try {
    const parsed = new URL(cleaned);
    const hostname = parsed.hostname.toLowerCase();
    
    // Check if hostname looks valid
    if (!hostname || hostname.length < 3 || (!hostname.includes('.') && !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname))) {
      return { isValid: false, canonicalUrl: cleaned, parsedUrl: null, error: 'Invalid hostname format or missing top-level domain' };
    }

    return {
      isValid: true,
      canonicalUrl: cleaned,
      parsedUrl: parsed
    };
  } catch (err: any) {
    return {
      isValid: false,
      canonicalUrl: cleaned,
      parsedUrl: null,
      error: `Malformed URL: ${err.message || 'Unable to parse URL structure'}`
    };
  }
}

/**
 * Checks if string is an IPv4 or IPv6 address or hexadecimal IP
 */
function isIpAddress(hostname: string): boolean {
  // IPv4 regex (including octal or decimal representation)
  const ipv4Pattern = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  // IPv6 check
  const ipv6Pattern = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
  // Hexadecimal IP pattern (e.g., 0x7f.0x00.0x00.0x01)
  const hexPattern = /^0x[0-9a-fA-F]{1,8}(\.0x[0-9a-fA-F]{1,8}){3}$/;

  return ipv4Pattern.test(hostname) || ipv6Pattern.test(hostname) || hexPattern.test(hostname);
}

/**
 * Main feature extraction engine for 16 standardized URL features
 */
export function extractUrlFeatures(rawUrl: string): {
  vector: URLFeatureVector;
  details: FeatureDetail[];
  entropyScore: number;
  brandSimilarityMatch: { impersonatedBrand: string; similarityScore: number } | null;
  parsedUrl: URL;
} {
  const norm = normalizeAndValidateUrl(rawUrl);
  if (!norm.isValid || !norm.parsedUrl) {
    throw new Error(norm.error || 'Invalid URL supplied for feature extraction');
  }

  const parsed = norm.parsedUrl;
  const canonicalUrl = norm.canonicalUrl;
  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname.toLowerCase();
  const search = parsed.search.toLowerCase();
  const fullUrlLower = canonicalUrl.toLowerCase();

  // 1. IP Address check
  const hasIp = isIpAddress(hostname);
  const having_ip_address = hasIp ? 1 : 0;

  // 2. URL Length (<54: 0, 54-75: 0.5, >75: 1)
  const urlLen = canonicalUrl.length;
  let url_length = 0;
  if (urlLen > 75) url_length = 1.0;
  else if (urlLen >= 54) url_length = 0.5;
  else url_length = 0.0;

  // 3. URL Shortener Service
  const isShortener = SHORTENER_DOMAINS.has(hostname) || Array.from(SHORTENER_DOMAINS).some(d => hostname.endsWith('.' + d));
  const shortening_service = isShortener ? 1.0 : 0.0;

  // 4. '@' Symbol in URL
  const hasAt = canonicalUrl.includes('@');
  const having_at_symbol = hasAt ? 1.0 : 0.0;

  // 5. Double Slash Redirect '//' after scheme (e.g. http://site.com//other)
  const doubleSlashPos = fullUrlLower.indexOf('//', 8);
  const double_slash_redirecting = doubleSlashPos !== -1 ? 1.0 : 0.0;

  // 6. Prefix / Suffix Dash '-' in Domain
  const hasDashInDomain = hostname.includes('-');
  const prefix_suffix_dash = hasDashInDomain ? 1.0 : 0.0;

  // 7. Subdomain Count (e.g. sub.sub2.example.com)
  const parts = hostname.split('.');
  let sub_domain_count = 0.0;
  if (hasIp) {
    sub_domain_count = 1.0;
  } else if (parts.length > 3) {
    sub_domain_count = 1.0; // 2+ subdomains e.g. a.b.c.com
  } else if (parts.length === 3) {
    // Check if it's ccTLD like .co.uk or .com.br
    const isCcTld = ['co.uk', 'com.au', 'com.br', 'co.jp', 'org.uk'].some(s => hostname.endsWith(s));
    sub_domain_count = isCcTld ? 0.0 : 0.5; // Single subdomain e.g. blog.google.com
  } else {
    sub_domain_count = 0.0; // standard root domain
  }

  // 8. SSL / HTTPS State
  const isHttps = parsed.protocol === 'https:';
  const ssl_final_state = isHttps ? 0.0 : 1.0; // 0 is safe (HTTPS), 1 is danger (HTTP)

  // 9. Domain TLD Risk
  const tld = parts[parts.length - 1];
  const isSuspiciousTld = SUSPICIOUS_TLDS.has(tld);
  const domain_registration_tld = isSuspiciousTld ? 1.0 : 0.0;

  // 10. Non-Standard Port
  let port_presence = 0.0;
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    port_presence = 1.0;
  }

  // 11. 'https' token inside Domain Name (e.g. https-paypal-verify.com)
  const httpsInHost = hostname.includes('https') || hostname.includes('http');
  const https_token_in_domain = httpsInHost ? 1.0 : 0.0;

  // 12. Sensitive Keywords in path or search query
  let keywordMatchCount = 0;
  for (const kw of SENSITIVE_KEYWORDS) {
    if (fullUrlLower.includes(kw)) {
      keywordMatchCount++;
    }
  }
  const sensitive_keywords = keywordMatchCount >= 2 ? 1.0 : keywordMatchCount === 1 ? 0.5 : 0.0;

  // 13. Digit-to-Letter Ratio
  const digits = (canonicalUrl.match(/\d/g) || []).length;
  const letters = (canonicalUrl.match(/[a-zA-Z]/g) || []).length;
  const digitRatio = letters > 0 ? digits / letters : (digits > 0 ? 1 : 0);
  const digit_to_letter_ratio = digitRatio > 0.25 ? 1.0 : digitRatio > 0.12 ? 0.5 : 0.0;

  // 14. Abnormal Special Characters / Punycode / Encoded Hex
  const hasPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');
  const hasExcessHex = (canonicalUrl.match(/%[0-9a-fA-F]{2}/g) || []).length > 2;
  const hasAbnormalChars = /[\^`~|<>{}\\]/.test(canonicalUrl);
  const abnormal_special_chars = (hasPunycode || hasExcessHex || hasAbnormalChars) ? 1.0 : 0.0;

  // 15. Shannon URL Entropy
  const entropy = calculateShannonEntropy(canonicalUrl);
  let url_entropy = 0.0;
  if (entropy > 4.4) url_entropy = 1.0;
  else if (entropy >= 3.9) url_entropy = 0.5;
  else url_entropy = 0.0;

  // 16. Anchor / Nested redirection / Dangerous extensions
  const hasSuspiciousParams = /redirect=|url=|return_to=|goto=|dest=https?:\/\//i.test(search);
  const hasDangerousExt = /\.(exe|scr|apk|vbs|bat|msi|cmd|pif)(\?|$)/i.test(pathname);
  const hasNestedPhp = (pathname.match(/\.php/g) || []).length > 1;
  const anchor_request_heuristics = (hasSuspiciousParams || hasDangerousExt || hasNestedPhp) ? 1.0 : 0.0;

  // Brand impersonation heuristic check
  let brandSimilarityMatch: { impersonatedBrand: string; similarityScore: number } | null = null;
  for (const brand of TARGET_BRANDS) {
    const matchedToken = brand.tokens.find(t => fullUrlLower.includes(t));
    if (matchedToken) {
      // Check if it is actually the official domain
      const isOfficial = hostname.endsWith(brand.name.toLowerCase().replace(/\s+/g, '') + '.com') ||
                         hostname === brand.name.toLowerCase().replace(/\s+/g, '') + '.com';
      if (!isOfficial) {
        brandSimilarityMatch = {
          impersonatedBrand: brand.name,
          similarityScore: 0.92
        };
        break;
      }
    }
  }

  const vector: URLFeatureVector = {
    having_ip_address,
    url_length,
    shortening_service,
    having_at_symbol,
    double_slash_redirecting,
    prefix_suffix_dash,
    sub_domain_count,
    ssl_final_state,
    domain_registration_tld,
    port_presence,
    https_token_in_domain,
    sensitive_keywords,
    digit_to_letter_ratio,
    abnormal_special_chars,
    url_entropy,
    anchor_request_heuristics
  };

  const details: FeatureDetail[] = [
    {
      key: 'having_ip_address',
      name: 'IP Address as Hostname',
      category: 'Structural',
      value: having_ip_address,
      rawValue: hasIp ? `IP (${hostname})` : `Domain (${hostname})`,
      status: having_ip_address === 1 ? 'DANGER' : 'SAFE',
      weight: 0.082,
      description: 'Checks if the website uses an IP address directly instead of a registered domain name.',
      riskExplanation: having_ip_address === 1 ? 'Host is a raw IP address; heavily correlated with credential stealing and rogue command servers.' : 'Legitimate named domain hierarchy.'
    },
    {
      key: 'url_length',
      name: 'URL Character Length',
      category: 'Structural',
      value: url_length,
      rawValue: `${urlLen} characters`,
      status: url_length === 1 ? 'DANGER' : url_length === 0.5 ? 'WARNING' : 'SAFE',
      weight: 0.068,
      description: 'Legitimate URLs are typically concise (<54 chars), whereas phishing URLs often exceed 75 chars to hide destination.',
      riskExplanation: url_length === 1 ? `Excessive length (${urlLen} chars) often hides malicious query parameters or deceptive subpaths.` : 'Standard, concise URL length.'
    },
    {
      key: 'shortening_service',
      name: 'URL Shortener Redirection',
      category: 'Structural',
      value: shortening_service,
      rawValue: isShortener ? `Shortener (${hostname})` : 'Direct Domain',
      status: shortening_service === 1 ? 'DANGER' : 'SAFE',
      weight: 0.075,
      description: 'Detects redirection services like bit.ly or tinyurl used by attackers to mask the ultimate target destination.',
      riskExplanation: shortening_service === 1 ? 'URL shortener obscures true landing page and SSL certificate details.' : 'Direct, uncloaked domain target.'
    },
    {
      key: 'having_at_symbol',
      name: '@ Symbol In URL',
      category: 'Lexical',
      value: having_at_symbol,
      rawValue: hasAt ? 'Present (@)' : 'None',
      status: having_at_symbol === 1 ? 'DANGER' : 'SAFE',
      weight: 0.054,
      description: 'Browsers ignore all characters prior to "@" in URLs, allowing attackers to spoof reputable brand names in front.',
      riskExplanation: having_at_symbol === 1 ? 'Contains "@" symbol; everything before "@" is ignored by the browser parser.' : 'No prefix spoofing symbol detected.'
    },
    {
      key: 'double_slash_redirecting',
      name: 'Double Slash Redirection (//)',
      category: 'Structural',
      value: double_slash_redirecting,
      rawValue: double_slash_redirecting === 1 ? `Found at index ${doubleSlashPos}` : 'Normal',
      status: double_slash_redirecting === 1 ? 'DANGER' : 'SAFE',
      weight: 0.059,
      description: 'Checks for "//" redirect sequence embedded downstream within the URL path.',
      riskExplanation: double_slash_redirecting === 1 ? 'Path contains "//" redirect token causing browser to jump to third-party host.' : 'Normal forward slash hierarchy.'
    },
    {
      key: 'prefix_suffix_dash',
      name: 'Hyphen (-) in Domain Name',
      category: 'Lexical',
      value: prefix_suffix_dash,
      rawValue: hasDashInDomain ? `Dash present (${hostname})` : 'Clean domain',
      status: prefix_suffix_dash === 1 ? 'WARNING' : 'SAFE',
      weight: 0.071,
      description: 'Attackers frequently use hyphens (e.g. paypal-security, bank-verify) to create deceptive lookalike domains.',
      riskExplanation: prefix_suffix_dash === 1 ? 'Domain contains hyphenated words; common characteristic in typosquatting.' : 'Standard single-token or standard brand domain.'
    },
    {
      key: 'sub_domain_count',
      name: 'Subdomain Hierarchy Depth',
      category: 'Structural',
      value: sub_domain_count,
      rawValue: `${parts.length - 2} subdomain(s)`,
      status: sub_domain_count === 1 ? 'DANGER' : sub_domain_count === 0.5 ? 'WARNING' : 'SAFE',
      weight: 0.089,
      description: 'Multi-level nested subdomains are often created on free hosting providers to mimic genuine brand paths.',
      riskExplanation: sub_domain_count === 1 ? 'Deep nested subdomains (>2) used to obscure real base domain ownership.' : 'Normal domain hierarchy.'
    },
    {
      key: 'ssl_final_state',
      name: 'HTTPS / SSL Transport State',
      category: 'Protocol & Security',
      value: ssl_final_state,
      rawValue: isHttps ? 'HTTPS (Encrypted)' : 'HTTP (Unencrypted)',
      status: ssl_final_state === 1 ? 'DANGER' : 'SAFE',
      weight: 0.095,
      description: 'Verifies whether communication is secured with HTTPS encryption certificate.',
      riskExplanation: ssl_final_state === 1 ? 'Plain HTTP protocol. No TLS/SSL certificate protection.' : 'Secured via standard HTTPS protocol.'
    },
    {
      key: 'domain_registration_tld',
      name: 'Suspicious / High-Risk TLD',
      category: 'Protocol & Security',
      value: domain_registration_tld,
      rawValue: `.${tld}`,
      status: domain_registration_tld === 1 ? 'DANGER' : 'SAFE',
      weight: 0.063,
      description: 'Certain TLDs (.xyz, .top, .buzz, .tk, .zip) have disproportionately high abuse and phishing rates.',
      riskExplanation: domain_registration_tld === 1 ? `TLD .${tld} is in the high-risk abuse registry list.` : `TLD .${tld} has established reputation.`
    },
    {
      key: 'port_presence',
      name: 'Non-Standard TCP Port',
      category: 'Protocol & Security',
      value: port_presence,
      rawValue: parsed.port ? `Port :${parsed.port}` : 'Standard (80/443)',
      status: port_presence === 1 ? 'DANGER' : 'SAFE',
      weight: 0.048,
      description: 'Checks if connection routes through non-standard web ports (e.g. 8080, 8888, 21).',
      riskExplanation: port_presence === 1 ? `Non-standard port (${parsed.port}) indicates anomalous server or rogue proxy.` : 'Standard web ports 80/443.'
    },
    {
      key: 'https_token_in_domain',
      name: '"HTTPS" Token in Hostname Body',
      category: 'Lexical',
      value: https_token_in_domain,
      rawValue: httpsInHost ? 'Present in domain' : 'None',
      status: https_token_in_domain === 1 ? 'DANGER' : 'SAFE',
      weight: 0.078,
      description: 'Fraudulent sites often insert the string "https" into the hostname (e.g. https-login-portal.com) to trick users.',
      riskExplanation: https_token_in_domain === 1 ? 'Misleading "https" token embedded in hostname text.' : 'No deceptive protocol token in domain.'
    },
    {
      key: 'sensitive_keywords',
      name: 'Credential Lure Keywords',
      category: 'Content & Heuristic',
      value: sensitive_keywords,
      rawValue: `${keywordMatchCount} trigger word(s)`,
      status: sensitive_keywords === 1 ? 'DANGER' : sensitive_keywords === 0.5 ? 'WARNING' : 'SAFE',
      weight: 0.086,
      description: 'Evaluates occurrence of high-risk security trigger words (login, verify, billing, banking, authenticate).',
      riskExplanation: sensitive_keywords >= 0.5 ? `Detected ${keywordMatchCount} security/authentication lures in path/query.` : 'No sensitive credential trigger terms.'
    },
    {
      key: 'digit_to_letter_ratio',
      name: 'Digit-to-Letter Ratio',
      category: 'Lexical',
      value: digit_to_letter_ratio,
      rawValue: `${(digitRatio * 100).toFixed(1)}% digits`,
      status: digit_to_letter_ratio === 1 ? 'DANGER' : digit_to_letter_ratio === 0.5 ? 'WARNING' : 'SAFE',
      weight: 0.052,
      description: 'Automated phishing generation algorithms (DGA) insert high percentages of numbers in URLs.',
      riskExplanation: digit_to_letter_ratio >= 0.5 ? `High proportion of numerical digits (${(digitRatio * 100).toFixed(1)}%) typical of algorithmically generated URLs.` : 'Natural lexical balance.'
    },
    {
      key: 'abnormal_special_chars',
      name: 'Punycode / Abnormal Characters',
      category: 'Lexical',
      value: abnormal_special_chars,
      rawValue: hasPunycode ? 'Punycode (IDN)' : hasExcessHex ? 'Excess Hex %xx' : 'Standard ASCII',
      status: abnormal_special_chars === 1 ? 'DANGER' : 'SAFE',
      weight: 0.061,
      description: 'Flags homograph attacks (xn--), internationalized domain manipulation, or heavily obfuscated hex sequences.',
      riskExplanation: abnormal_special_chars === 1 ? 'Internationalized / encoded homograph detected; high risk of visual brand spoofing.' : 'Standard clean character set.'
    },
    {
      key: 'url_entropy',
      name: 'Shannon URL Entropy Score',
      category: 'Content & Heuristic',
      value: url_entropy,
      rawValue: `${entropy.toFixed(2)} bits`,
      status: url_entropy === 1 ? 'DANGER' : url_entropy === 0.5 ? 'WARNING' : 'SAFE',
      weight: 0.084,
      description: 'Measures information randomness. High entropy (>4.3) indicates machine-generated paths or encrypted payloads.',
      riskExplanation: url_entropy >= 0.5 ? `High entropy (${entropy.toFixed(2)}) indicates character randomness and payload obfuscation.` : `Low/normal entropy (${entropy.toFixed(2)}), typical of human-authored URLs.`
    },
    {
      key: 'anchor_request_heuristics',
      name: 'Redirection / Executable Heuristics',
      category: 'Content & Heuristic',
      value: anchor_request_heuristics,
      rawValue: hasSuspiciousParams ? 'Open Redirect query' : hasDangerousExt ? 'Executable Ext' : 'Standard Request',
      status: anchor_request_heuristics === 1 ? 'DANGER' : 'SAFE',
      weight: 0.063,
      description: 'Checks for open-redirect parameters (?dest=http), embedded executable extensions (.exe, .scr), or script chaining.',
      riskExplanation: anchor_request_heuristics === 1 ? 'Identified open redirection query pattern or unsafe resource extension.' : 'Normal resource routing.'
    }
  ];

  return {
    vector,
    details,
    entropyScore: entropy,
    brandSimilarityMatch,
    parsedUrl: parsed
  };
}
