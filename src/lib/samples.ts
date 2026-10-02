export interface DemoUrlSample {
  id: string;
  category: 'Legitimate Corporate' | 'Banking Phish' | 'Brand Impersonation' | 'IP & Unsecured' | 'Shortener Harvester' | 'Punycode Homograph';
  url: string;
  expectedClass: 'LEGITIMATE' | 'PHISHING' | 'SUSPICIOUS';
  description: string;
  threatIndicators: string[];
}

export const SAMPLE_URLS: DemoUrlSample[] = [
  // Legitimate
  {
    id: 'legit-1',
    category: 'Legitimate Corporate',
    url: 'https://www.google.com/search?q=cybersecurity+defense',
    expectedClass: 'LEGITIMATE',
    description: 'Official Google search engine with valid TLS and standard root domain structure.',
    threatIndicators: ['Clean domain hierarchy', 'Active HTTPS encryption', 'Standard character set']
  },
  {
    id: 'legit-2',
    category: 'Legitimate Corporate',
    url: 'https://github.com/torvalds/linux/commits/master',
    expectedClass: 'LEGITIMATE',
    description: 'Official GitHub repository URL with trusted TLD and standard paths.',
    threatIndicators: ['Official .com domain', 'Valid TLS certificate', 'No obfuscation']
  },
  {
    id: 'legit-3',
    category: 'Legitimate Corporate',
    url: 'https://en.wikipedia.org/wiki/Random_forest',
    expectedClass: 'LEGITIMATE',
    description: 'Wikipedia reference article on Random Forest ensemble algorithms.',
    threatIndicators: ['Trusted .org TLD', 'Strict HTTPS', 'Direct canonical path']
  },
  {
    id: 'legit-4',
    category: 'Legitimate Corporate',
    url: 'https://www.bankofamerica.com/online-banking/sign-in',
    expectedClass: 'LEGITIMATE',
    description: 'Official Bank of America sign-in page with verified organization ownership.',
    threatIndicators: ['Official banking domain', 'Extended Validation SSL', 'Clean host token']
  },

  // Phishing / Malicious Samples
  {
    id: 'phish-1',
    category: 'Brand Impersonation',
    url: 'http://paypal-security-update.account-verify.xyz/login.php?session=928471928471029384&redirect=auth',
    expectedClass: 'PHISHING',
    description: 'Classic PayPal credential harvesting lure with hyphenated subdomains and .xyz TLD.',
    threatIndicators: ['Deceptive hyphenated brand domain', 'Suspicious .xyz TLD', 'Unencrypted HTTP', 'Deep nested subdomains', 'High URL entropy']
  },
  {
    id: 'phish-2',
    category: 'IP & Unsecured',
    url: 'http://192.168.1.184:8080/secure/bankofamerica-login/verify_account.php',
    expectedClass: 'PHISHING',
    description: 'Direct IPv4 hosting on non-standard port :8080 spoofing Bank of America authentication.',
    threatIndicators: ['Raw IP address used as host', 'Non-standard port 8080', 'Unencrypted HTTP', 'Brand name embedded in path']
  },
  {
    id: 'phish-3',
    category: 'Brand Impersonation',
    url: 'https://appleid.apple.com-recover-auth-session.top/verify?token=847294827',
    expectedClass: 'PHISHING',
    description: 'Apple ID phishing campaign using lookalike domain with high-risk .top registry.',
    threatIndicators: ['Subdomain prepended with appleid.apple.com', 'High risk .top TLD', 'Multiple security lure keywords', 'Excessive URL length']
  },
  {
    id: 'phish-4',
    category: 'Shortener Harvester',
    url: 'https://tinyurl.com/bank-urgent-reset-pin?redirect=http://stealer-server.net',
    expectedClass: 'PHISHING',
    description: 'Shortener redirection hiding downstream credential theft target with open redirect.',
    threatIndicators: ['URL Shortening service masking target', 'Open redirect parameter (?redirect=)', 'Urgency lure keywords in path']
  },
  {
    id: 'phish-5',
    category: 'Punycode Homograph',
    url: 'http://xn--gogle-qpa.com/login/service-login/auth?user=napoleon',
    expectedClass: 'PHISHING',
    description: 'IDN Punycode homograph attack mimicking Google (gôgle.com) with foreign Cyrillic/Latin characters.',
    threatIndicators: ['Punycode xn-- prefix (Homograph spoofing)', 'Unencrypted HTTP protocol', 'Credential harvesting keywords']
  },
  {
    id: 'phish-6',
    category: 'Banking Phish',
    url: 'http://chase-online-secure-banking.auth-webscr.club/account/suspended-verify.php?id=94829',
    expectedClass: 'PHISHING',
    description: 'Deceptive Chase online banking phishing site featuring urgent suspension scare tactics.',
    threatIndicators: ['Suspicious .club TLD', 'Excessive hyphenation', 'Urgent scareware keywords (suspended, verify)', 'Unencrypted HTTP']
  }
];
