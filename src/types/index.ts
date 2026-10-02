/**
 * Core type definitions for Phishing Website Detection System
 * Using Random Forest Ensemble Theory
 */

export interface URLFeatureVector {
  // 1. IP Address in Hostname (1 = Suspicious IP, 0 = Legitimate Domain)
  having_ip_address: number;
  // 2. URL Length (<54: 0, 54-75: 0.5, >75: 1)
  url_length: number;
  // 3. Shortening Service (bit.ly, tinyurl, etc. -> 1, 0)
  shortening_service: number;
  // 4. Having '@' symbol (1, 0)
  having_at_symbol: number;
  // 5. Double slash redirection after protocol (1, 0)
  double_slash_redirecting: number;
  // 6. Prefix / Suffix dash '-' in domain (1, 0)
  prefix_suffix_dash: number;
  // 7. Subdomain count (>2 subdomains -> 1, 1-2 -> 0.5, 0-1 -> 0)
  sub_domain_count: number;
  // 8. SSL / HTTPS protocol state (HTTP -> 1, HTTPS -> 0)
  ssl_final_state: number;
  // 9. Suspicious TLD (.xyz, .tk, .top, .buzz, etc. -> 1, 0)
  domain_registration_tld: number;
  // 10. Non-standard port presence (1, 0)
  port_presence: number;
  // 11. 'https' token in domain name (1, 0)
  https_token_in_domain: number;
  // 12. Sensitive credential/security keywords (login, bank, verify, update, etc. -> 1, 0)
  sensitive_keywords: number;
  // 13. Digit-to-letter ratio (> 0.25 -> 1, 0)
  digit_to_letter_ratio: number;
  // 14. Abnormal/Punycode/Hex characters (1, 0)
  abnormal_special_chars: number;
  // 15. Shannon URL Entropy (> 4.3 -> 1, 3.8-4.3 -> 0.5, <3.8 -> 0)
  url_entropy: number;
  // 16. Anchor / Nested redirection / Executable heuristics (1, 0)
  anchor_request_heuristics: number;
}

export type FeatureKey = keyof URLFeatureVector;

export interface FeatureDetail {
  key: FeatureKey;
  name: string;
  category: 'Structural' | 'Lexical' | 'Protocol & Security' | 'Content & Heuristic';
  value: number; // normalized 0 to 1
  rawValue: string | number | boolean;
  status: 'SAFE' | 'WARNING' | 'DANGER';
  weight: number; // Importance in Random Forest
  description: string;
  riskExplanation: string;
}

export type PredictionClass = 'LEGITIMATE' | 'PHISHING' | 'SUSPICIOUS';

export interface DecisionTreeNode {
  id: string;
  featureIndex?: number;
  featureName?: FeatureKey;
  threshold?: number;
  left?: DecisionTreeNode;
  right?: DecisionTreeNode;
  value?: number; // predicted probability / class (1 = phishing, 0 = legit)
  samples?: number;
  impurity?: number;
  isLeaf: boolean;
}

export interface TreeVote {
  treeId: number;
  vote: 'LEGITIMATE' | 'PHISHING';
  probability: number;
  depthReached: number;
  keySplitFeature?: string;
}

export interface ScanResult {
  id: string;
  url: string;
  canonicalUrl: string;
  domain: string;
  timestamp: string;
  prediction: PredictionClass;
  confidence: number; // e.g. 94.6% (never 100%)
  phishingProbability: number; // 0.0 - 1.0
  legitimateProbability: number; // 0.0 - 1.0
  riskScore: number; // 0 to 100
  featureVector: URLFeatureVector;
  features: FeatureDetail[];
  treeVotes: TreeVote[];
  treesPhishingVotes: number;
  treesLegitimateVotes: number;
  totalTrees: number;
  executionTimeMs: number;
  verdictReason: string;
  securityRecommendations: string[];
  entropyScore: number;
  trustScore: number; // 0 - 100 (e.g. 100 for clean, 0-30 for phishing)
  threatDatabases: {
    openPhish: 'Clean' | 'Flagged';
    urlhaus: 'Clean' | 'Flagged';
    googleSafeBrowsing: 'Clean' | 'Threat Match';
    domainAge: string;
  };
  brandSimilarityMatch?: {
    impersonatedBrand: string;
    similarityScore: number;
  } | null;
  safeBrowsingData?: {
    checked: boolean;
    isThreatFound: boolean;
    threatTypes?: string[];
    platformType?: string;
    cacheDuration?: string;
    apiSource: string;
    lookupTimestamp?: string;
  } | null;
  liveIntelligence?: {
    resolvedIp?: string;
    dnsStatus?: string;
    organization?: string;
    category?: string;
    googleVerified: boolean;
    summary?: string;
  } | null;
}

export interface ForestHyperparameters {
  nEstimators: number; // e.g. 25
  maxDepth: number; // e.g. 8
  minSamplesSplit: number; // e.g. 2
  maxFeatures: 'sqrt' | 'log2' | 'all';
  criterion: 'gini' | 'entropy';
}

export interface ModelPerformanceMetrics {
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  rocAuc: number;
  totalTrainingSamples: number;
  totalTestingSamples: number;
  confusionMatrix: {
    truePositive: number;
    falsePositive: number;
    trueNegative: number;
    falseNegative: number;
  };
  featureImportances: {
    key: FeatureKey;
    name: string;
    importance: number;
    category: string;
  }[];
}

export interface UserProfile {
  id: string;
  email: string;
  name: string;
  avatarUrl?: string;
  authProvider: 'google' | 'email';
  role: string;
  organization?: string;
  createdAt: string;
}

export interface ScanStats {
  totalScans: number;
  phishingDetected: number;
  legitimateDetected: number;
  suspiciousDetected: number;
  avgConfidence: number;
  avgResponseTimeMs: number;
}
