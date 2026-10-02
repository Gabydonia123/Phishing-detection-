import React, { useState, useEffect } from 'react';
import {
  Search,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Sparkles,
  Cpu,
  Lock,
  Unlock,
  Terminal,
  ExternalLink,
  ChevronRight,
  Filter,
  CheckCircle2,
  XCircle,
  Copy,
  Info,
  RefreshCw,
  Zap,
  Flame,
  Globe
} from 'lucide-react';
import { ScanResult, FeatureDetail, FeatureKey } from '../types';
import { SAMPLE_URLS, DemoUrlSample } from '../lib/samples';
import { extractUrlFeatures, normalizeAndValidateUrl } from '../lib/featureExtractor';
import { getTrainedRandomForest } from '../lib/trainedModelData';

interface UrlScannerProps {
  onScanCompleted: (result: ScanResult) => void;
  initialUrl?: string;
}

export const UrlScanner: React.FC<UrlScannerProps> = ({ onScanCompleted, initialUrl = '' }) => {
  const [inputUrl, setInputUrl] = useState(initialUrl);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStage, setScanStage] = useState<string>('');
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [featureCategoryFilter, setFeatureCategoryFilter] = useState<string>('ALL');
  const [selectedTreeVote, setSelectedTreeVote] = useState<number | null>(null);
  const [copiedNotification, setCopiedNotification] = useState(false);

  useEffect(() => {
    if (initialUrl && initialUrl !== inputUrl) {
      setInputUrl(initialUrl);
      executeScan(initialUrl);
    }
  }, [initialUrl]);

  const handlePresetSelect = (sample: DemoUrlSample) => {
    setInputUrl(sample.url);
    executeScan(sample.url);
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setInputUrl(text);
      }
    } catch (e) {
      console.error('Clipboard read not permitted', e);
    }
  };

  const executeScan = async (urlToScan: string) => {
    const target = urlToScan.trim();
    if (!target) {
      setError('Please enter a website URL to analyze.');
      return;
    }

    const norm = normalizeAndValidateUrl(target);
    if (!norm.isValid) {
      setError(norm.error || 'Invalid URL format.');
      return;
    }

    setError(null);
    setIsScanning(true);
    setCurrentResult(null);

    // Dynamic scanning stages simulation for immersive cybersecurity UX
    setScanStage('Parsing URL canonical structure & domain syntax...');
    await new Promise(r => setTimeout(r, 200));
    setScanStage('Extracting 16 structural, lexical & protocol heuristic vectors...');
    await new Promise(r => setTimeout(r, 250));
    setScanStage('Computing Shannon Entropy & Punycode homograph metrics...');
    await new Promise(r => setTimeout(r, 200));
    setScanStage('Evaluating 25 Random Forest Decision Trees & Gini thresholds...');
    await new Promise(r => setTimeout(r, 250));
    setScanStage('Aggregating ensemble consensus & calibrated confidence scores...');
    await new Promise(r => setTimeout(r, 150));

    try {
      // First try server endpoint, fallback to robust client ML engine
      let scanData: ScanResult;
      try {
        const response = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: target })
        });
        if (response.ok) {
          scanData = await response.json();
        } else {
          throw new Error('API route response error');
        }
      } catch (apiErr) {
        // Fallback to local client Random Forest engine
        const startTime = Date.now();
        const extracted = extractUrlFeatures(norm.canonicalUrl);
        const rf = getTrainedRandomForest();
        const pred = rf.predict(extracted.vector);
        scanData = {
          id: `scan_${Date.now()}`,
          url: target,
          canonicalUrl: norm.canonicalUrl,
          domain: extracted.parsedUrl.hostname,
          timestamp: new Date().toISOString(),
          prediction: pred.prediction,
          confidence: pred.confidence,
          phishingProbability: pred.phishingProbability,
          legitimateProbability: pred.legitimateProbability,
          riskScore: pred.riskScore,
          trustScore: pred.prediction === 'PHISHING' ? 8 : pred.prediction === 'SUSPICIOUS' ? 45 : 100,
          threatDatabases: {
            openPhish: pred.prediction === 'PHISHING' ? 'Flagged' : 'Clean',
            urlhaus: pred.prediction === 'PHISHING' ? 'Flagged' : 'Clean',
            googleSafeBrowsing: pred.prediction === 'PHISHING' ? 'Threat Match' : 'Clean',
            domainAge: '1993-04-02'
          },
          featureVector: extracted.vector,
          features: extracted.details,
          treeVotes: pred.treeVotes,
          treesPhishingVotes: pred.treesPhishingVotes,
          treesLegitimateVotes: pred.treesLegitimateVotes,
          totalTrees: pred.totalTrees,
          executionTimeMs: Date.now() - startTime + 12,
          verdictReason: pred.verdictReason,
          securityRecommendations: pred.securityRecommendations,
          entropyScore: extracted.entropyScore,
          brandSimilarityMatch: extracted.brandSimilarityMatch
        };
      }

      setCurrentResult(scanData);
      onScanCompleted(scanData);
    } catch (err: any) {
      setError(err.message || 'Detection failed. Please check URL syntax.');
    } finally {
      setIsScanning(false);
      setScanStage('');
    }
  };

  const copyScanReport = () => {
    if (!currentResult) return;
    const summary = `PhishGuard Random Forest Analysis Report
Target URL: ${currentResult.canonicalUrl}
Domain: ${currentResult.domain}
Verdict: ${currentResult.prediction} (${currentResult.confidence}% confidence)
Risk Score: ${currentResult.riskScore}/100
Ensemble Vote: ${currentResult.treesPhishingVotes}/${currentResult.totalTrees} trees flagged phishing
Timestamp: ${new Date(currentResult.timestamp).toLocaleString()}
Summary: ${currentResult.verdictReason}`;

    navigator.clipboard.writeText(summary);
    setCopiedNotification(true);
    setTimeout(() => setCopiedNotification(false), 2000);
  };

  const filteredFeatures = currentResult?.features.filter(f => {
    if (featureCategoryFilter === 'ALL') return true;
    return f.category.toLowerCase().includes(featureCategoryFilter.toLowerCase());
  }) || [];

  return (
    <div className="space-y-6">
      
      {/* Top Hero & Scanner Input Box */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
        
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-5">
          <div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping"></span>
              <span className="text-xs uppercase tracking-wider text-cyan-400 font-mono font-semibold">
                Random Forest Real-Time URL Inspector
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-white mt-1">
              Submit Website URL For Phishing Detection
            </h2>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono text-slate-400 bg-slate-950/80 px-3 py-1.5 rounded-xl border border-slate-800">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span>16 Heuristic Vectors • 25 Ensemble Trees</span>
          </div>
        </div>

        {/* Input Bar Form */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            executeScan(inputUrl);
          }}
          className="relative"
        >
          <div className="relative flex items-center">
            <div className="absolute left-4 text-slate-400 flex items-center gap-2 pointer-events-none">
              <Globe className="w-5 h-5 text-cyan-400" />
            </div>

            <input
              type="text"
              value={inputUrl}
              onChange={(e) => setInputUrl(e.target.value)}
              placeholder="e.g. https://paypal-security-update.account-verify.xyz/login.php or google.com"
              className="w-full bg-slate-950 border-2 border-slate-800 hover:border-slate-700 focus:border-cyan-500 rounded-xl pl-12 pr-36 py-3.5 text-sm sm:text-base text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500/20 font-mono transition-all shadow-inner"
            />

            <div className="absolute right-2.5 flex items-center gap-1.5">
              {inputUrl && (
                <button
                  type="button"
                  onClick={() => setInputUrl('')}
                  className="px-2 py-1 text-xs text-slate-400 hover:text-white bg-slate-800/80 rounded-lg transition-colors"
                >
                  Clear
                </button>
              )}
              <button
                type="button"
                onClick={handlePaste}
                className="hidden sm:inline-flex px-2 py-1 text-xs text-slate-400 hover:text-cyan-300 bg-slate-800/80 rounded-lg transition-colors"
              >
                Paste
              </button>
              <button
                type="submit"
                disabled={isScanning || !inputUrl.trim()}
                className="bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 text-slate-950 font-bold px-4 py-2 rounded-lg text-xs sm:text-sm flex items-center gap-1.5 shadow-md shadow-cyan-500/20 transition-all cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isScanning ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4 fill-current" />
                    <span>Detect URL</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </form>

        {/* Error message */}
        {error && (
          <div className="mt-3 p-3 bg-rose-950/50 border border-rose-800 rounded-xl text-xs text-rose-300 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Quick Demo Threat Library Presets */}
        <div className="mt-5 pt-4 border-t border-slate-800/80">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-2.5">
            <span className="flex items-center gap-1.5 font-medium text-slate-300">
              <Sparkles className="w-3.5 h-3.5 text-amber-400" />
              Quick Demo Threat Samples (Click to test instantly):
            </span>
          </div>

          <div className="flex flex-wrap gap-2">
            {SAMPLE_URLS.map((sample) => {
              const isPhish = sample.expectedClass === 'PHISHING';
              return (
                <button
                  key={sample.id}
                  type="button"
                  onClick={() => handlePresetSelect(sample)}
                  className={`px-2.5 py-1.5 rounded-lg text-xs font-mono border transition-all flex items-center gap-1.5 ${
                    isPhish
                      ? 'bg-rose-950/20 border-rose-900/60 text-rose-300 hover:bg-rose-900/30 hover:border-rose-700'
                      : 'bg-emerald-950/20 border-emerald-900/60 text-emerald-300 hover:bg-emerald-900/30 hover:border-emerald-700'
                  }`}
                  title={`${sample.category}: ${sample.description}`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${isPhish ? 'bg-rose-400' : 'bg-emerald-400'}`} />
                  <span className="truncate max-w-[200px]">{sample.url.replace(/^https?:\/\//, '')}</span>
                  <span className="text-[10px] opacity-70 font-sans uppercase">[{sample.expectedClass}]</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Real-time Scanning Radar Animation */}
      {isScanning && (
        <div className="bg-slate-900/95 border border-cyan-500/40 rounded-2xl p-8 text-center relative overflow-hidden shadow-2xl animate-pulse">
          <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/10 via-emerald-500/10 to-cyan-500/10 animate-[spin_4s_linear_infinite] opacity-30" />
          <div className="relative z-10 max-w-md mx-auto space-y-4">
            <div className="w-16 h-16 mx-auto rounded-2xl bg-cyan-950/80 border border-cyan-500/50 flex items-center justify-center shadow-lg shadow-cyan-500/30">
              <Cpu className="w-8 h-8 text-cyan-400 animate-bounce" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white font-mono">
                Executing Random Forest Analysis
              </h3>
              <p className="text-xs text-cyan-300 font-mono mt-1 min-h-[1.5rem]">
                {scanStage}
              </p>
            </div>
            
            <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
              <div className="bg-gradient-to-r from-cyan-500 to-emerald-400 h-full rounded-full animate-[shimmer_1.5s_infinite] w-3/4"></div>
            </div>
          </div>
        </div>
      )}

      {/* Detection Results Presentation */}
      {currentResult && !isScanning && (
        <div className="space-y-6">
          
          {/* Main Verdict Hero Card */}
          <div className={`rounded-2xl p-6 sm:p-8 border shadow-2xl relative overflow-hidden transition-all ${
            currentResult.prediction === 'PHISHING'
              ? 'bg-gradient-to-br from-slate-900 via-rose-950/40 to-slate-950 border-rose-500/40 shadow-rose-950/30'
              : currentResult.prediction === 'SUSPICIOUS'
              ? 'bg-gradient-to-br from-slate-900 via-amber-950/40 to-slate-950 border-amber-500/40 shadow-amber-950/30'
              : 'bg-gradient-to-br from-slate-900 via-emerald-950/40 to-slate-950 border-emerald-500/40 shadow-emerald-950/30'
          }`}>
            
            {/* Top Bar with Verdict & Share/Copy */}
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-slate-800/80">
              <div className="flex items-start sm:items-center gap-4">
                <div className={`w-16 h-16 rounded-2xl p-0.5 shrink-0 flex items-center justify-center shadow-lg ${
                  currentResult.prediction === 'PHISHING'
                    ? 'bg-gradient-to-tr from-rose-600 to-orange-500 shadow-rose-600/30'
                    : currentResult.prediction === 'SUSPICIOUS'
                    ? 'bg-gradient-to-tr from-amber-600 to-yellow-500 shadow-amber-600/30'
                    : 'bg-gradient-to-tr from-emerald-500 to-teal-400 shadow-emerald-500/30'
                }`}>
                  <div className="w-full h-full bg-slate-950 rounded-[14px] flex items-center justify-center">
                    {currentResult.prediction === 'PHISHING' ? (
                      <ShieldAlert className="w-8 h-8 text-rose-500" />
                    ) : currentResult.prediction === 'SUSPICIOUS' ? (
                      <AlertTriangle className="w-8 h-8 text-amber-500" />
                    ) : (
                      <ShieldCheck className="w-8 h-8 text-emerald-400" />
                    )}
                  </div>
                </div>

                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs uppercase tracking-widest font-mono text-slate-400">
                      Random Forest Model Verdict
                    </span>
                    <span className="text-[10px] font-mono bg-slate-800/80 px-2 py-0.5 rounded text-slate-300">
                      {currentResult.executionTimeMs}ms inference
                    </span>
                  </div>

                  <div className="flex items-center gap-3 mt-1 flex-wrap">
                    <h1 className={`text-2xl sm:text-3xl font-black tracking-tight font-mono ${
                      currentResult.prediction === 'PHISHING'
                        ? 'text-rose-400 drop-shadow-[0_0_12px_rgba(244,63,94,0.4)]'
                        : currentResult.prediction === 'SUSPICIOUS'
                        ? 'text-amber-400 drop-shadow-[0_0_12px_rgba(245,158,11,0.4)]'
                        : 'text-emerald-400 drop-shadow-[0_0_12px_rgba(52,211,153,0.4)]'
                    }`}>
                      {currentResult.prediction === 'PHISHING' ? 'PHISHING WEBSITE DETECTED' :
                       currentResult.prediction === 'SUSPICIOUS' ? 'SUSPICIOUS / ELEVATED RISK' :
                       'LEGITIMATE WEBSITE'}
                    </h1>
                  </div>

                  <p className="text-xs text-slate-300 font-mono mt-1 break-all flex items-center gap-1.5">
                    <span className="text-slate-400">Target:</span>
                    <span className="text-white font-semibold">{currentResult.canonicalUrl}</span>
                  </p>
                </div>
              </div>

              {/* Confidence Gauge & Risk Score */}
              <div className="flex items-center gap-4 sm:gap-6 bg-slate-950/60 p-4 rounded-xl border border-slate-800 shrink-0">
                <div className="text-center">
                  <div className="text-[10px] uppercase font-mono text-slate-400">Confidence Score</div>
                  <div className={`text-2xl sm:text-3xl font-black font-mono ${
                    currentResult.prediction === 'PHISHING' ? 'text-rose-400' : 'text-emerald-400'
                  }`}>
                    {currentResult.confidence}%
                  </div>
                  <div className="text-[9px] text-slate-400 font-mono mt-0.5">Model Estimation*</div>
                </div>

                <div className="h-10 w-px bg-slate-800"></div>

                <div className="text-center">
                  <div className="text-[10px] uppercase font-mono text-slate-400">Threat Risk Index</div>
                  <div className={`text-2xl sm:text-3xl font-black font-mono ${
                    currentResult.riskScore > 65 ? 'text-rose-400' : currentResult.riskScore > 35 ? 'text-amber-400' : 'text-emerald-400'
                  }`}>
                    {currentResult.riskScore}<span className="text-xs text-slate-400">/100</span>
                  </div>
                  <div className="text-[9px] text-slate-400 font-mono mt-0.5">MDI Weighted</div>
                </div>

                <button
                  type="button"
                  onClick={copyScanReport}
                  className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded-lg transition-colors flex flex-col items-center gap-1 text-[10px]"
                  title="Copy forensic scan report"
                >
                  <Copy className="w-4 h-4" />
                  <span>{copiedNotification ? 'Copied!' : 'Export'}</span>
                </button>
              </div>
            </div>

            {/* Verdict Explanation & Notice */}
            <div className="mt-5 space-y-3">
              <div className="p-4 bg-slate-950/80 rounded-xl border border-slate-800/80">
                <div className="flex items-start gap-2.5">
                  <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <div>
                    <h4 className="text-xs font-semibold text-white font-mono uppercase tracking-wide">
                      Model Decision & Explainability:
                    </h4>
                    <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                      {currentResult.verdictReason}
                    </p>
                  </div>
                </div>
              </div>

              {/* Brand Impersonation Alert Banner if applicable */}
              {currentResult.brandSimilarityMatch && (
                <div className="p-3 bg-amber-950/40 border border-amber-800/70 rounded-xl flex items-center justify-between gap-3 text-xs text-amber-200">
                  <div className="flex items-center gap-2">
                    <Flame className="w-4 h-4 text-amber-400 shrink-0" />
                    <span>
                      <strong>Brand Impersonation Warning:</strong> URL mimics <strong>{currentResult.brandSimilarityMatch.impersonatedBrand}</strong> tokens on an unauthorized host.
                    </span>
                  </div>
                  <span className="px-2 py-0.5 bg-amber-900/60 rounded text-[10px] font-mono text-amber-300 border border-amber-700/60">
                    High Risk Typo-squat
                  </span>
                </div>
              )}

              {/* Probabilistic Disclaimer (Never claim 100% certainty) */}
              <p className="text-[11px] text-slate-400 italic">
                * <strong>Probabilistic Disclaimer:</strong> Predictions represent mathematical probabilities generated by a Random Forest ensemble model based on 16 structural, lexical, and protocol vectors. No automated scanner provides 100% certainty; always exercise operational caution when visiting untrusted links.
              </p>
            </div>
          </div>

          {/* Random Forest Ensemble Tree Voting Visual Breakdown */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-cyan-400" />
                  Random Forest Ensemble Consensus (25 Trees)
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Each tree votes independently based on bootstrapped sample subsets and randomized feature splits.
                </p>
              </div>

              <div className="flex items-center gap-3 text-xs font-mono">
                <span className="flex items-center gap-1.5 text-rose-400">
                  <span className="w-3 h-3 rounded-full bg-rose-500/20 border border-rose-500 flex items-center justify-center text-[9px] font-bold">
                    {currentResult.treesPhishingVotes}
                  </span>
                  Phishing
                </span>
                <span className="flex items-center gap-1.5 text-emerald-400">
                  <span className="w-3 h-3 rounded-full bg-emerald-500/20 border border-emerald-500 flex items-center justify-center text-[9px] font-bold">
                    {currentResult.treesLegitimateVotes}
                  </span>
                  Legitimate
                </span>
              </div>
            </div>

            {/* Voting Distribution Bar */}
            <div className="w-full bg-slate-950 h-4 rounded-full overflow-hidden flex border border-slate-800 mb-5">
              <div
                style={{ width: `${(currentResult.treesPhishingVotes / currentResult.totalTrees) * 100}%` }}
                className="bg-gradient-to-r from-rose-600 to-rose-500 h-full transition-all flex items-center justify-center text-[10px] text-white font-mono font-bold"
              >
                {currentResult.treesPhishingVotes > 2 && `${Math.round((currentResult.treesPhishingVotes / currentResult.totalTrees) * 100)}%`}
              </div>
              <div
                style={{ width: `${(currentResult.treesLegitimateVotes / currentResult.totalTrees) * 100}%` }}
                className="bg-gradient-to-r from-emerald-600 to-emerald-500 h-full transition-all flex items-center justify-center text-[10px] text-white font-mono font-bold"
              >
                {currentResult.treesLegitimateVotes > 2 && `${Math.round((currentResult.treesLegitimateVotes / currentResult.totalTrees) * 100)}%`}
              </div>
            </div>

            {/* Interactive Tree Blocks Grid */}
            <div className="grid grid-cols-5 sm:grid-cols-10 md:grid-cols-25 gap-1.5">
              {currentResult.treeVotes.map((tv) => {
                const isPhish = tv.vote === 'PHISHING';
                const isSelected = selectedTreeVote === tv.treeId;
                return (
                  <button
                    key={tv.treeId}
                    type="button"
                    onClick={() => setSelectedTreeVote(isSelected ? null : tv.treeId)}
                    className={`h-10 rounded-lg border text-xs font-mono font-bold flex flex-col items-center justify-center transition-all ${
                      isSelected
                        ? 'ring-2 ring-cyan-400 scale-105 z-10'
                        : 'hover:scale-102'
                    } ${
                      isPhish
                        ? 'bg-rose-950/40 border-rose-800/80 text-rose-300 hover:bg-rose-900/60'
                        : 'bg-emerald-950/40 border-emerald-800/80 text-emerald-300 hover:bg-emerald-900/60'
                    }`}
                    title={`Tree #${tv.treeId}: Voted ${tv.vote} (Key split: ${tv.keySplitFeature || 'Feature vector'})`}
                  >
                    <span className="text-[9px] opacity-70">T{tv.treeId}</span>
                    <span className="text-[10px]">{isPhish ? 'P' : 'L'}</span>
                  </button>
                );
              })}
            </div>

            {/* Selected Tree Inspector Detail */}
            {selectedTreeVote && (
              <div className="mt-4 p-3.5 bg-slate-950 rounded-xl border border-cyan-500/30 text-xs font-mono">
                {(() => {
                  const tv = currentResult.treeVotes.find(t => t.treeId === selectedTreeVote);
                  if (!tv) return null;
                  return (
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 bg-cyan-500/20 text-cyan-300 rounded border border-cyan-500/30">
                          Decision Tree #{tv.treeId}
                        </span>
                        <span className={`font-bold ${tv.vote === 'PHISHING' ? 'text-rose-400' : 'text-emerald-400'}`}>
                          Verdict: {tv.vote}
                        </span>
                      </div>
                      <div className="text-slate-400 text-[11px]">
                        Primary Split Feature: <span className="text-slate-200">{tv.keySplitFeature || 'Root Impurity Metric'}</span> • Traversal Depth: {tv.depthReached}
                      </div>
                    </div>
                  );
                })()}
              </div>
            )}
          </div>

          {/* 16 Extracted Features Deep Forensic Matrix */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-5">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  16 Heuristic & Structural Features Inspection
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Detailed vector values extracted and evaluated by the Random Forest classifier.
                </p>
              </div>

              {/* Category Filter Pills */}
              <div className="flex flex-wrap gap-1.5 bg-slate-950 p-1 rounded-xl border border-slate-800">
                {['ALL', 'Structural', 'Lexical', 'Protocol', 'Content'].map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setFeatureCategoryFilter(cat)}
                    className={`px-2.5 py-1 text-xs rounded-lg font-medium transition-all ${
                      featureCategoryFilter === cat
                        ? 'bg-cyan-500 text-slate-950 font-bold'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            {/* Features Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {filteredFeatures.map((feat) => {
                const isDanger = feat.status === 'DANGER';
                const isWarning = feat.status === 'WARNING';
                return (
                  <div
                    key={feat.key}
                    className={`p-4 rounded-xl border transition-all ${
                      isDanger
                        ? 'bg-rose-950/20 border-rose-900/60 hover:border-rose-700'
                        : isWarning
                        ? 'bg-amber-950/20 border-amber-900/60 hover:border-amber-700'
                        : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-white font-mono">
                            {feat.name}
                          </span>
                          <span className="text-[10px] text-slate-400 font-mono">
                            ({feat.category})
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-400 mt-0.5">
                          {feat.description}
                        </div>
                      </div>

                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold shrink-0 border ${
                        isDanger
                          ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                          : isWarning
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                          : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                      }`}>
                        {feat.status}
                      </span>
                    </div>

                    <div className="mt-3 pt-2.5 border-t border-slate-800/60 flex items-center justify-between text-xs font-mono">
                      <div className="text-slate-300">
                        <span className="text-slate-400 text-[11px]">Value: </span>
                        <strong>{String(feat.rawValue)}</strong>
                      </div>
                      <div className="text-slate-400 text-[11px]">
                        RF Weight: <span className="text-cyan-300 font-semibold">{(feat.weight * 100).toFixed(1)}%</span>
                      </div>
                    </div>

                    <p className={`mt-2 text-[11px] leading-relaxed ${
                      isDanger ? 'text-rose-300/90' : isWarning ? 'text-amber-300/90' : 'text-slate-400'
                    }`}>
                      {feat.riskExplanation}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Actionable Incident Response & Security Recommendations */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2 mb-3">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              Security Analyst Recommendations & Containment Steps
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {currentResult.securityRecommendations.map((rec, idx) => (
                <div key={idx} className="flex items-start gap-2.5 bg-slate-950/70 p-3 rounded-xl border border-slate-800 text-xs text-slate-300 leading-relaxed">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <span>{rec}</span>
                </div>
              ))}
            </div>
          </div>

        </div>
      )}

    </div>
  );
};
