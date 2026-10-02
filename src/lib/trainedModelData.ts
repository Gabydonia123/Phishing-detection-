import { TrainingSample, RandomForestClassifier, FEATURE_KEYS } from './randomForest';
import { URLFeatureVector } from '../types';

/**
 * Benchmark phishing dataset synthesized from standard UC Irvine / PhishTank feature distributions
 */
export function generateBenchmarkDataset(): TrainingSample[] {
  const dataset: TrainingSample[] = [];

  // 1. Phishing feature patterns (IPs, long URLs, shorteners, missing SSL, lure keywords, high entropy, dashes)
  const phishingArchetypes: Partial<URLFeatureVector>[] = [
    // Archetype A: Raw IP phishing login
    { having_ip_address: 1, ssl_final_state: 1, sensitive_keywords: 1, url_entropy: 0.5, sub_domain_count: 1 },
    // Archetype B: Paypal typosquat with dashes and long URL
    { prefix_suffix_dash: 1, url_length: 1, sensitive_keywords: 1, sub_domain_count: 1, https_token_in_domain: 1, digit_to_letter_ratio: 0.5 },
    // Archetype C: Shortened link with open redirect
    { shortening_service: 1, anchor_request_heuristics: 1, sensitive_keywords: 0.5, url_entropy: 0.5 },
    // Archetype D: Suspicious TLD (.xyz, .top) with credential prompt
    { domain_registration_tld: 1, sensitive_keywords: 1, url_length: 0.5, sub_domain_count: 0.5, url_entropy: 0.5 },
    // Archetype E: @ symbol prefix spoof
    { having_at_symbol: 1, url_length: 1, ssl_final_state: 1, double_slash_redirecting: 1 },
    // Archetype F: High digit ratio and punycode homograph
    { abnormal_special_chars: 1, digit_to_letter_ratio: 1, url_entropy: 1, prefix_suffix_dash: 1 },
    // Archetype G: Non standard port with HTTP and admin keywords
    { port_presence: 1, ssl_final_state: 1, sensitive_keywords: 1, url_length: 0.5 },
    // Archetype H: Deep multi-subdomains with account verification
    { sub_domain_count: 1, sensitive_keywords: 1, url_length: 1, prefix_suffix_dash: 1, url_entropy: 0.5 }
  ];

  // 2. Legitimate feature patterns (Standard domains, HTTPS, low length, zero IP, zero shorteners, standard TLDs)
  const legitArchetypes: Partial<URLFeatureVector>[] = [
    // Archetype A: Standard corporate / search engine
    { having_ip_address: 0, url_length: 0, shortening_service: 0, having_at_symbol: 0, ssl_final_state: 0, domain_registration_tld: 0, sub_domain_count: 0, url_entropy: 0 },
    // Archetype B: Multi-page e-commerce or docs with subpaths
    { having_ip_address: 0, url_length: 0.5, ssl_final_state: 0, domain_registration_tld: 0, sub_domain_count: 0.5, digit_to_letter_ratio: 0, url_entropy: 0 },
    // Archetype C: Cloud portal with login keyword but clean root domain and HTTPS
    { having_ip_address: 0, sensitive_keywords: 0.5, ssl_final_state: 0, domain_registration_tld: 0, sub_domain_count: 0.5, url_length: 0.5 },
    // Archetype D: Standard educational / government portal
    { having_ip_address: 0, url_length: 0, ssl_final_state: 0, domain_registration_tld: 0, sub_domain_count: 0 }
  ];

  function createFullVector(partial: Partial<URLFeatureVector>, isPhish: boolean): URLFeatureVector {
    const vec: any = {};
    for (const k of FEATURE_KEYS) {
      if (partial[k] !== undefined) {
        vec[k] = partial[k];
      } else {
        // Add realistic noise
        const noise = Math.random();
        if (isPhish) {
          vec[k] = noise > 0.7 ? 1 : noise > 0.4 ? 0.5 : 0;
        } else {
          vec[k] = noise > 0.9 ? 0.5 : 0;
        }
      }
    }
    return vec as URLFeatureVector;
  }

  // Generate 400 training samples
  for (let i = 0; i < 200; i++) {
    const template = phishingArchetypes[i % phishingArchetypes.length];
    dataset.push({
      vector: createFullVector(template, true),
      label: 1
    });
  }

  for (let i = 0; i < 200; i++) {
    const template = legitArchetypes[i % legitArchetypes.length];
    dataset.push({
      vector: createFullVector(template, false),
      label: 0
    });
  }

  return dataset;
}

// Global singleton instance of trained Random Forest
let globalRandomForest: RandomForestClassifier | null = null;

export function getTrainedRandomForest(): RandomForestClassifier {
  if (!globalRandomForest || !globalRandomForest.isTrained) {
    globalRandomForest = new RandomForestClassifier({
      nEstimators: 25,
      maxDepth: 7,
      minSamplesSplit: 2,
      maxFeatures: 'sqrt',
      criterion: 'gini'
    });
    const dataset = generateBenchmarkDataset();
    globalRandomForest.train(dataset);
  }
  return globalRandomForest;
}

export function retrainGlobalModel(hyperparameters: {
  nEstimators: number;
  maxDepth: number;
  minSamplesSplit: number;
}): { forest: RandomForestClassifier; metrics: any } {
  globalRandomForest = new RandomForestClassifier({
    nEstimators: hyperparameters.nEstimators,
    maxDepth: hyperparameters.maxDepth,
    minSamplesSplit: hyperparameters.minSamplesSplit,
    maxFeatures: 'sqrt',
    criterion: 'gini'
  });
  const dataset = generateBenchmarkDataset();
  const metrics = globalRandomForest.train(dataset);
  return { forest: globalRandomForest, metrics };
}
