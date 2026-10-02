import React, { useState, useMemo } from 'react';
import {
  Sliders,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RotateCcw,
  Sparkles,
  Zap,
  Cpu
} from 'lucide-react';
import { URLFeatureVector, FeatureKey } from '../types';
import { FEATURE_KEYS, FEATURE_NAMES } from '../lib/randomForest';
import { getTrainedRandomForest } from '../lib/trainedModelData';

export const ThreatPlayground: React.FC = () => {
  const defaultVector: URLFeatureVector = {
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
  };

  const [features, setFeatures] = useState<URLFeatureVector>(defaultVector);

  const handleToggle = (key: FeatureKey, val: number) => {
    setFeatures(prev => ({
      ...prev,
      [key]: val
    }));
  };

  const handleReset = () => {
    setFeatures(defaultVector);
  };

  const rf = getTrainedRandomForest();
  const predictionResult = useMemo(() => {
    return rf.predict(features);
  }, [features, rf]);

  return (
    <div className="space-y-6">
      
      {/* Header Box */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              <span className="text-xs uppercase tracking-wider text-cyan-400 font-mono font-semibold">
                Feature Sensitivity & Simulation Lab
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-white mt-1">
              Random Forest Feature Threat Playground
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Toggle vector characteristics to observe how individual feature combinations alter the Random Forest ensemble prediction in real time.
            </p>
          </div>

          <button
            type="button"
            onClick={handleReset}
            className="px-3.5 py-1.5 bg-slate-950 border border-slate-800 hover:border-slate-700 rounded-lg text-xs font-mono text-slate-300 hover:text-white transition-colors flex items-center gap-1.5"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Reset to Clean State
          </button>
        </div>
      </div>

      {/* Live Real-time Simulation Status Card */}
      <div className={`rounded-2xl p-6 border shadow-2xl transition-all ${
        predictionResult.prediction === 'PHISHING'
          ? 'bg-gradient-to-r from-slate-900 via-rose-950/40 to-slate-900 border-rose-500/40'
          : predictionResult.prediction === 'SUSPICIOUS'
          ? 'bg-gradient-to-r from-slate-900 via-amber-950/40 to-slate-900 border-amber-500/40'
          : 'bg-gradient-to-r from-slate-900 via-emerald-950/40 to-slate-900 border-emerald-500/40'
      }`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${
              predictionResult.prediction === 'PHISHING' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40' :
              predictionResult.prediction === 'SUSPICIOUS' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40' :
              'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
            }`}>
              {predictionResult.prediction === 'PHISHING' ? <ShieldAlert className="w-6 h-6" /> :
               predictionResult.prediction === 'SUSPICIOUS' ? <AlertTriangle className="w-6 h-6" /> :
               <ShieldCheck className="w-6 h-6" />}
            </div>

            <div>
              <div className="text-xs uppercase font-mono text-slate-400">Simulated Ensemble Verdict</div>
              <div className={`text-2xl font-black font-mono mt-0.5 ${
                predictionResult.prediction === 'PHISHING' ? 'text-rose-400' :
                predictionResult.prediction === 'SUSPICIOUS' ? 'text-amber-400' :
                'text-emerald-400'
              }`}>
                {predictionResult.prediction}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-6 bg-slate-950/80 p-3.5 rounded-xl border border-slate-800 font-mono">
            <div className="text-center">
              <div className="text-[10px] text-slate-400 uppercase">Confidence</div>
              <div className="text-xl font-bold text-white">{predictionResult.confidence}%</div>
            </div>
            <div className="h-8 w-px bg-slate-800"></div>
            <div className="text-center">
              <div className="text-[10px] text-slate-400 uppercase">Tree Votes</div>
              <div className="text-sm font-bold text-slate-200">
                <span className="text-rose-400">{predictionResult.treesPhishingVotes}P</span> / <span className="text-emerald-400">{predictionResult.treesLegitimateVotes}L</span>
              </div>
            </div>
          </div>
        </div>

        <p className="text-xs text-slate-300 mt-4 leading-relaxed bg-slate-950/60 p-3 rounded-lg border border-slate-800/80 font-mono">
          {predictionResult.verdictReason}
        </p>
      </div>

      {/* 16 Vector Toggle Grid */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2 mb-4">
          <Cpu className="w-4 h-4 text-cyan-400" />
          Interactive 16-Vector Feature Matrix
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
          {FEATURE_KEYS.map((key) => {
            const val = features[key];
            const isDanger = val === 1;
            const isWarning = val === 0.5;

            return (
              <div
                key={key}
                className={`p-3.5 rounded-xl border transition-all ${
                  isDanger
                    ? 'bg-rose-950/30 border-rose-800/80'
                    : isWarning
                    ? 'bg-amber-950/30 border-amber-800/80'
                    : 'bg-slate-950/60 border-slate-800/80'
                }`}
              >
                <div className="text-xs font-bold text-white font-mono mb-2 truncate" title={FEATURE_NAMES[key]}>
                  {FEATURE_NAMES[key]}
                </div>

                {/* 3-State Toggle Buttons (Safe, Moderate, Dangerous) */}
                <div className="grid grid-cols-3 gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-[10px] font-mono">
                  <button
                    type="button"
                    onClick={() => handleToggle(key, 0)}
                    className={`py-1 rounded text-center transition-colors ${
                      val === 0 ? 'bg-emerald-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    Clean
                  </button>
                  <button
                    type="button"
                    onClick={() => handleToggle(key, 0.5)}
                    className={`py-1 rounded text-center transition-colors ${
                      val === 0.5 ? 'bg-amber-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    Warn
                  </button>
                  <button
                    type="button"
                    onClick={() => handleToggle(key, 1)}
                    className={`py-1 rounded text-center transition-colors ${
                      val === 1 ? 'bg-rose-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    Danger
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

    </div>
  );
};
