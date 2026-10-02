import React, { useState, useEffect } from 'react';
import { SimpleNavbar } from './components/SimpleNavbar';
import { SimpleAuth } from './components/SimpleAuth';
import { PhishingChecker } from './components/PhishingChecker';
import { UserProfile, ScanResult } from './types';
import { getStoredSession, saveSession } from './lib/authStore';

const HISTORY_STORAGE_KEY = 'phish_guard_recent_scans_v2';

// Preset matching the exact URLs from the user's uploaded Screenshot 2
const SEED_RECENT_SCANS: ScanResult[] = [
  {
    id: 'rec-1',
    url: 'https://enraleigh.us14.list-manage.com/track/click?u=8492048&id=4829',
    canonicalUrl: 'https://enraleigh.us14.list-manage.com/track/click?u=8492048&id=4829',
    domain: 'enraleigh.us14.list-manage.com',
    timestamp: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
    prediction: 'SUSPICIOUS',
    confidence: 84.6,
    phishingProbability: 0.846,
    legitimateProbability: 0.154,
    riskScore: 85,
    trustScore: 45,
    threatDatabases: {
      openPhish: 'Clean',
      urlhaus: 'Flagged',
      googleSafeBrowsing: 'Clean',
      domainAge: '2021-04-18'
    },
    featureVector: {
      having_ip_address: 0,
      url_length: 1,
      shortening_service: 0,
      having_at_symbol: 0,
      double_slash_redirecting: 0,
      prefix_suffix_dash: 1,
      sub_domain_count: 1,
      ssl_final_state: 0,
      domain_registration_tld: 0,
      port_presence: 0,
      https_token_in_domain: 0,
      sensitive_keywords: 0.5,
      digit_to_letter_ratio: 0.5,
      abnormal_special_chars: 0,
      url_entropy: 0.5,
      anchor_request_heuristics: 1
    },
    features: [],
    treeVotes: [],
    treesPhishingVotes: 21,
    treesLegitimateVotes: 4,
    totalTrees: 25,
    executionTimeMs: 12,
    verdictReason: 'Tracking link with nested redirection parameters and high-frequency token length.',
    securityRecommendations: ['Inspect landing URL before logging in'],
    entropyScore: 4.12,
    brandSimilarityMatch: null
  },
  {
    id: 'rec-2',
    url: 'https://qrco.de/bfHvn6',
    canonicalUrl: 'https://qrco.de/bfHvn6',
    domain: 'qrco.de',
    timestamp: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
    prediction: 'LEGITIMATE',
    confidence: 96.8,
    phishingProbability: 0.032,
    legitimateProbability: 0.968,
    riskScore: 3,
    trustScore: 100,
    threatDatabases: {
      openPhish: 'Clean',
      urlhaus: 'Clean',
      googleSafeBrowsing: 'Clean',
      domainAge: '2016-08-11'
    },
    featureVector: {
      having_ip_address: 0,
      url_length: 0,
      shortening_service: 0,
      having_at_symbol: 0,
      double_slash_redirecting: 0,
      prefix_suffix_dash: 0,
      sub_domain_count: 0,
      ssl_final_state: 0,
      domain_registration_tld: 0,
      port_presence: 0,
      https_token_in_domain: 0,
      sensitive_keywords: 0,
      digit_to_letter_ratio: 0,
      abnormal_special_chars: 0,
      url_entropy: 0,
      anchor_request_heuristics: 0
    },
    features: [],
    treeVotes: [],
    treesPhishingVotes: 0,
    treesLegitimateVotes: 25,
    totalTrees: 25,
    executionTimeMs: 8,
    verdictReason: 'Standard QR dynamic routing gateway with valid TLS certificate.',
    securityRecommendations: ['Clear to proceed'],
    entropyScore: 3.25,
    brandSimilarityMatch: null
  },
  {
    id: 'rec-3',
    url: 'https://gateway.lighthouse.storage/ipfs/bafybeic7r9842',
    canonicalUrl: 'https://gateway.lighthouse.storage/ipfs/bafybeic7r9842',
    domain: 'gateway.lighthouse.storage',
    timestamp: new Date(Date.now() - 1000 * 60 * 25).toISOString(),
    prediction: 'SUSPICIOUS',
    confidence: 88.2,
    phishingProbability: 0.882,
    legitimateProbability: 0.118,
    riskScore: 88,
    trustScore: 35,
    threatDatabases: {
      openPhish: 'Clean',
      urlhaus: 'Flagged',
      googleSafeBrowsing: 'Clean',
      domainAge: '2023-01-14'
    },
    featureVector: {
      having_ip_address: 0,
      url_length: 1,
      shortening_service: 0,
      having_at_symbol: 0,
      double_slash_redirecting: 0,
      prefix_suffix_dash: 0,
      sub_domain_count: 1,
      ssl_final_state: 0,
      domain_registration_tld: 0,
      port_presence: 0,
      https_token_in_domain: 0,
      sensitive_keywords: 0,
      digit_to_letter_ratio: 0.5,
      abnormal_special_chars: 0,
      url_entropy: 1,
      anchor_request_heuristics: 0
    },
    features: [],
    treeVotes: [],
    treesPhishingVotes: 22,
    treesLegitimateVotes: 3,
    totalTrees: 25,
    executionTimeMs: 14,
    verdictReason: 'Decentralized IPFS gateway storage used for payload hosting or unverified content.',
    securityRecommendations: ['Verify file hash before opening'],
    entropyScore: 4.54,
    brandSimilarityMatch: null
  },
  {
    id: 'rec-4',
    url: 'https://apple.ent.box.com/f',
    canonicalUrl: 'https://apple.ent.box.com/f',
    domain: 'apple.ent.box.com',
    timestamp: new Date(Date.now() - 1000 * 60 * 40).toISOString(),
    prediction: 'PHISHING',
    confidence: 94.2,
    phishingProbability: 0.942,
    legitimateProbability: 0.058,
    riskScore: 94,
    trustScore: 8,
    threatDatabases: {
      openPhish: 'Flagged',
      urlhaus: 'Flagged',
      googleSafeBrowsing: 'Threat Match',
      domainAge: '2024-05-10 (Recent / High Risk)'
    },
    featureVector: {
      having_ip_address: 0,
      url_length: 0.5,
      shortening_service: 0,
      having_at_symbol: 0,
      double_slash_redirecting: 0,
      prefix_suffix_dash: 0,
      sub_domain_count: 1,
      ssl_final_state: 0,
      domain_registration_tld: 0,
      port_presence: 0,
      https_token_in_domain: 0,
      sensitive_keywords: 0.5,
      digit_to_letter_ratio: 0,
      abnormal_special_chars: 0,
      url_entropy: 0.5,
      anchor_request_heuristics: 0
    },
    features: [],
    treeVotes: [],
    treesPhishingVotes: 24,
    treesLegitimateVotes: 1,
    totalTrees: 25,
    executionTimeMs: 10,
    verdictReason: 'Subdomain spoofing Apple branding on a third-party enterprise cloud storage portal.',
    securityRecommendations: ['Do not provide Apple ID credentials'],
    entropyScore: 3.88,
    brandSimilarityMatch: { impersonatedBrand: 'Apple', similarityScore: 0.91 }
  },
  {
    id: 'rec-5',
    url: 'https://accounts.google.com/v3/signin/identifier',
    canonicalUrl: 'https://accounts.google.com/v3/signin/identifier',
    domain: 'accounts.google.com',
    timestamp: new Date(Date.now() - 1000 * 60 * 55).toISOString(),
    prediction: 'LEGITIMATE',
    confidence: 98.4,
    phishingProbability: 0.016,
    legitimateProbability: 0.984,
    riskScore: 2,
    trustScore: 100,
    threatDatabases: {
      openPhish: 'Clean',
      urlhaus: 'Clean',
      googleSafeBrowsing: 'Clean',
      domainAge: '1997-09-15'
    },
    featureVector: {
      having_ip_address: 0,
      url_length: 0.5,
      shortening_service: 0,
      having_at_symbol: 0,
      double_slash_redirecting: 0,
      prefix_suffix_dash: 0,
      sub_domain_count: 0.5,
      ssl_final_state: 0,
      domain_registration_tld: 0,
      port_presence: 0,
      https_token_in_domain: 0,
      sensitive_keywords: 0.5,
      digit_to_letter_ratio: 0,
      abnormal_special_chars: 0,
      url_entropy: 0,
      anchor_request_heuristics: 0
    },
    features: [],
    treeVotes: [],
    treesPhishingVotes: 0,
    treesLegitimateVotes: 25,
    totalTrees: 25,
    executionTimeMs: 9,
    verdictReason: 'Official Google Account authentication portal with verified domain authority.',
    securityRecommendations: ['Official Google authentication'],
    entropyScore: 3.45,
    brandSimilarityMatch: null
  },
  {
    id: 'rec-6',
    url: 'https://www.instagram.com/stories/gokus...',
    canonicalUrl: 'https://www.instagram.com/stories/gokus...',
    domain: 'www.instagram.com',
    timestamp: new Date(Date.now() - 1000 * 60 * 70).toISOString(),
    prediction: 'LEGITIMATE',
    confidence: 97.9,
    phishingProbability: 0.021,
    legitimateProbability: 0.979,
    riskScore: 2,
    trustScore: 100,
    threatDatabases: {
      openPhish: 'Clean',
      urlhaus: 'Clean',
      googleSafeBrowsing: 'Clean',
      domainAge: '2004-06-04'
    },
    featureVector: {
      having_ip_address: 0,
      url_length: 0.5,
      shortening_service: 0,
      having_at_symbol: 0,
      double_slash_redirecting: 0,
      prefix_suffix_dash: 0,
      sub_domain_count: 0.5,
      ssl_final_state: 0,
      domain_registration_tld: 0,
      port_presence: 0,
      https_token_in_domain: 0,
      sensitive_keywords: 0,
      digit_to_letter_ratio: 0,
      abnormal_special_chars: 0,
      url_entropy: 0,
      anchor_request_heuristics: 0
    },
    features: [],
    treeVotes: [],
    treesPhishingVotes: 0,
    treesLegitimateVotes: 25,
    totalTrees: 25,
    executionTimeMs: 11,
    verdictReason: 'Legitimate social media destination on official Instagram domain.',
    securityRecommendations: ['Safe to browse'],
    entropyScore: 3.32,
    brandSimilarityMatch: null
  },
  {
    id: 'rec-7',
    url: 'https://ar.friendshipquiz2023.com/fr/sync-data',
    canonicalUrl: 'https://ar.friendshipquiz2023.com/fr/sync-data',
    domain: 'ar.friendshipquiz2023.com',
    timestamp: new Date(Date.now() - 1000 * 60 * 95).toISOString(),
    prediction: 'SUSPICIOUS',
    confidence: 86.5,
    phishingProbability: 0.865,
    legitimateProbability: 0.135,
    riskScore: 86,
    trustScore: 40,
    threatDatabases: {
      openPhish: 'Clean',
      urlhaus: 'Flagged',
      googleSafeBrowsing: 'Clean',
      domainAge: '2023-04-12'
    },
    featureVector: {
      having_ip_address: 0,
      url_length: 0.5,
      shortening_service: 0,
      having_at_symbol: 0,
      double_slash_redirecting: 0,
      prefix_suffix_dash: 1,
      sub_domain_count: 0.5,
      ssl_final_state: 0,
      domain_registration_tld: 0,
      port_presence: 0,
      https_token_in_domain: 0,
      sensitive_keywords: 0,
      digit_to_letter_ratio: 0.5,
      abnormal_special_chars: 0,
      url_entropy: 0.5,
      anchor_request_heuristics: 0
    },
    features: [],
    treeVotes: [],
    treesPhishingVotes: 21,
    treesLegitimateVotes: 4,
    totalTrees: 25,
    executionTimeMs: 13,
    verdictReason: 'Social engineering quiz domain featuring numerical year suffix and hyphens.',
    securityRecommendations: ['Exercise caution before entering details'],
    entropyScore: 3.95,
    brandSimilarityMatch: null
  }
];

export default function App() {
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(() => getStoredSession());
  const [showAuthModal, setShowAuthModal] = useState<boolean>(false);
  const [recentScans, setRecentScans] = useState<ScanResult[]>(() => {
    try {
      const saved = localStorage.getItem(HISTORY_STORAGE_KEY);
      if (saved) {
        return JSON.parse(saved);
      }
    } catch (e) {
      console.error(e);
    }
    return SEED_RECENT_SCANS;
  });

  useEffect(() => {
    try {
      localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(recentScans));
    } catch (e) {
      console.error(e);
    }
  }, [recentScans]);

  const handleLoginSuccess = (user: UserProfile) => {
    setCurrentUser(user);
    saveSession(user);
    setShowAuthModal(false);
  };

  const handleLogout = () => {
    setCurrentUser(null);
    saveSession(null);
  };

  const handleScanCompleted = (newResult: ScanResult) => {
    setRecentScans(prev => {
      const filtered = prev.filter(r => r.canonicalUrl !== newResult.canonicalUrl);
      return [newResult, ...filtered].slice(0, 50);
    });
  };

  // If user requested login or isn't logged in and wants auth
  if (showAuthModal || !currentUser) {
    return (
      <div className="min-h-screen bg-[#F8FAFC] text-slate-900 font-sans flex flex-col justify-between">
        <header className="bg-[#0F172A] text-white py-4 px-6 border-b border-slate-800 flex items-center justify-between">
          <div className="font-bold text-sm tracking-tight font-sans flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-blue-500"></span>
            PHISHING WEBSITE DETECTION SYSTEM
          </div>
          {currentUser && (
            <button
              onClick={() => setShowAuthModal(false)}
              className="text-xs text-slate-400 hover:text-white"
            >
              Back to Checker
            </button>
          )}
        </header>

        <main className="flex-1 flex items-center justify-center p-4">
          <SimpleAuth onLoginSuccess={handleLoginSuccess} />
        </main>

        <footer className="text-center py-6 text-xs text-slate-400 border-t border-slate-200">
          Phishing Website Detection System • Safe & Secure URL Analysis
        </footer>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#F8FAFC] text-slate-900 font-sans flex flex-col justify-between">
      
      {/* Top Header matching Screenshots */}
      <SimpleNavbar
        user={currentUser}
        onLogout={handleLogout}
        onOpenLogin={() => setShowAuthModal(true)}
      />

      {/* Main Link Checker Page */}
      <main className="flex-1 max-w-5xl w-full mx-auto px-4 sm:px-6 py-8 sm:py-12">
        <PhishingChecker
          onScanCompleted={handleScanCompleted}
          recentScans={recentScans}
        />
      </main>

      {/* Footer */}
      <footer className="w-full bg-white border-t border-slate-200 py-6 text-center text-xs text-slate-500 font-sans mt-12">
        <div className="max-w-5xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <span className="font-semibold text-slate-700">
            Phishing Website Detection System
          </span>
          <span className="text-slate-400">
            16-Feature Random Forest Machine Learning Threat Engine
          </span>
        </div>
      </footer>

    </div>
  );
}
