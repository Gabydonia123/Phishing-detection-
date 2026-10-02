import React, { useState } from 'react';
import {
  Cpu,
  BarChart3,
  GitBranch,
  Sliders,
  Sparkles,
  RefreshCw,
  CheckCircle2,
  BookOpen,
  Info,
  Layers,
  ArrowRight
} from 'lucide-react';
import { getTrainedRandomForest, retrainGlobalModel } from '../lib/trainedModelData';
import { DecisionTreeNode, FeatureKey } from '../types';
import { FEATURE_NAMES } from '../lib/randomForest';

export const ModelStudio: React.FC = () => {
  const [rf, setRf] = useState(() => getTrainedRandomForest());
  const [selectedTreeIndex, setSelectedTreeIndex] = useState<number>(0);
  const [nEstimators, setNEstimators] = useState<number>(rf.hyperparameters.nEstimators || 25);
  const [maxDepth, setMaxDepth] = useState<number>(rf.hyperparameters.maxDepth || 7);
  const [minSamplesSplit, setMinSamplesSplit] = useState<number>(rf.hyperparameters.minSamplesSplit || 2);
  const [isRetraining, setIsRetraining] = useState(false);
  const [retrainSuccessMsg, setRetrainSuccessMsg] = useState<string | null>(null);

  const metrics = rf.trainingMetrics;
  const currentTree = rf.trees[selectedTreeIndex] || rf.trees[0];

  const handleRetrain = async () => {
    setIsRetraining(true);
    setRetrainSuccessMsg(null);

    await new Promise(r => setTimeout(r, 600));

    try {
      const { forest, metrics: newMetrics } = retrainGlobalModel({
        nEstimators,
        maxDepth,
        minSamplesSplit
      });
      setRf(forest);
      setSelectedTreeIndex(0);
      setRetrainSuccessMsg(`Random Forest successfully retrained with ${forest.trees.length} decision trees. New accuracy: ${(newMetrics.accuracy * 100).toFixed(1)}%.`);
    } catch (e: any) {
      console.error(e);
    } finally {
      setIsRetraining(false);
    }
  };

  // Helper to render tree nodes hierarchically
  const renderTreeNode = (node: DecisionTreeNode | undefined, depth: number = 0, path: string = 'root') => {
    if (!node) return null;

    const isLeaf = node.isLeaf || !node.featureName;
    const isPhishLeaf = isLeaf && (node.value === 1 || (node.value !== undefined && node.value >= 0.5));

    return (
      <div key={path} className="flex flex-col items-center my-1.5 font-mono">
        <div className={`p-2.5 rounded-xl border text-xs text-center max-w-[240px] shadow-sm transition-all ${
          isLeaf
            ? isPhishLeaf
              ? 'bg-rose-950/60 border-rose-700 text-rose-300'
              : 'bg-emerald-950/60 border-emerald-700 text-emerald-300'
            : 'bg-slate-950 border-cyan-500/40 text-slate-200'
        }`}>
          {isLeaf ? (
            <div>
              <div className="font-bold flex items-center justify-center gap-1">
                <span>{isPhishLeaf ? '⚠️ LEAF: PHISHING' : '🛡️ LEAF: LEGITIMATE'}</span>
              </div>
              <div className="text-[10px] text-slate-400 mt-0.5">
                Samples: {node.samples} • Gini: {node.impurity ?? 0}
              </div>
            </div>
          ) : (
            <div>
              <div className="font-bold text-cyan-300 text-[11px]">
                {FEATURE_NAMES[node.featureName as FeatureKey] || node.featureName}
              </div>
              <div className="text-[10px] text-slate-300 mt-0.5">
                Split Threshold: &le; {node.threshold}
              </div>
              <div className="text-[9px] text-slate-400 mt-0.5">
                Gini: {node.impurity} • N={node.samples}
              </div>
            </div>
          )}
        </div>

        {/* Child branches */}
        {!isLeaf && (node.left || node.right) && depth < 3 && (
          <div className="w-full flex justify-around mt-2 pt-2 border-t border-slate-800 relative">
            {node.left && (
              <div className="flex flex-col items-center px-2">
                <span className="text-[9px] text-emerald-400 font-mono mb-1">&le; {node.threshold} (True)</span>
                {renderTreeNode(node.left, depth + 1, `${path}_L`)}
              </div>
            )}
            {node.right && (
              <div className="flex flex-col items-center px-2">
                <span className="text-[9px] text-rose-400 font-mono mb-1">&gt; {node.threshold} (False)</span>
                {renderTreeNode(node.right, depth + 1, `${path}_R`)}
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-6">
      
      {/* Header Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <span className="text-xs uppercase tracking-wider text-cyan-400 font-mono font-semibold">
                Machine Learning Model Architecture
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-white mt-1">
              Random Forest Ensemble & Decision Trees
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Explainable ensemble learning with bagging, random feature subspaces, and Gini impurity optimization.
            </p>
          </div>

          <div className="flex items-center gap-2 bg-slate-950 px-3 py-1.5 rounded-xl border border-slate-800 text-xs font-mono text-emerald-400">
            <CheckCircle2 className="w-4 h-4" />
            <span>Ensemble Trained & Validated</span>
          </div>
        </div>
      </div>

      {/* Model Benchmark Performance Metrics */}
      {metrics && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
            <div className="text-slate-400 text-xs font-mono">Classification Accuracy</div>
            <div className="text-2xl font-black text-emerald-400 font-mono mt-1">
              {(metrics.accuracy * 100).toFixed(1)}%
            </div>
            <div className="text-[10px] text-slate-400 font-mono mt-0.5">PhishTank Benchmark</div>
          </div>

          <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
            <div className="text-slate-400 text-xs font-mono">Precision (Phishing)</div>
            <div className="text-2xl font-black text-cyan-400 font-mono mt-1">
              {(metrics.precision * 100).toFixed(1)}%
            </div>
            <div className="text-[10px] text-slate-400 font-mono mt-0.5">Low False Positives</div>
          </div>

          <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
            <div className="text-slate-400 text-xs font-mono">Recall (Detection Rate)</div>
            <div className="text-2xl font-black text-indigo-400 font-mono mt-1">
              {(metrics.recall * 100).toFixed(1)}%
            </div>
            <div className="text-[10px] text-slate-400 font-mono mt-0.5">Threat Catch Rate</div>
          </div>

          <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl">
            <div className="text-slate-400 text-xs font-mono">F1-Score Harmonic</div>
            <div className="text-2xl font-black text-teal-400 font-mono mt-1">
              {(metrics.f1Score * 100).toFixed(1)}%
            </div>
            <div className="text-[10px] text-slate-400 font-mono mt-0.5">Balanced metric</div>
          </div>

          <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl col-span-2 sm:col-span-1">
            <div className="text-slate-400 text-xs font-mono">ROC-AUC Score</div>
            <div className="text-2xl font-black text-purple-400 font-mono mt-1">
              {metrics.rocAuc.toFixed(3)}
            </div>
            <div className="text-[10px] text-slate-400 font-mono mt-0.5">Discrimination index</div>
          </div>
        </div>
      )}

      {/* 2-Column Grid: Decision Tree Explorer + MDI Feature Importance */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left: Decision Tree Visualizer */}
        <div className="lg:col-span-7 bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
                  <GitBranch className="w-4 h-4 text-cyan-400" />
                  Decision Tree Structure Explorer
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Inspect the split criteria, Gini impurity, and leaf boundaries for individual trees.
                </p>
              </div>

              {/* Tree Selector Dropdown */}
              <select
                value={selectedTreeIndex}
                onChange={(e) => setSelectedTreeIndex(Number(e.target.value))}
                className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-cyan-300 font-mono focus:outline-none focus:border-cyan-500"
              >
                {rf.trees.map((_, idx) => (
                  <option key={idx} value={idx}>
                    Tree #{idx + 1} of {rf.trees.length}
                  </option>
                ))}
              </select>
            </div>

            {/* Tree Graph Container */}
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 overflow-x-auto min-h-[340px] flex items-center justify-center">
              {currentTree?.root ? (
                renderTreeNode(currentTree.root, 0, 'root')
              ) : (
                <div className="text-xs font-mono text-slate-400">Tree data unavailable</div>
              )}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/80 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Showing top 3 hierarchy levels of Tree #{selectedTreeIndex + 1}</span>
            <span className="font-mono text-cyan-400">Max Depth: {currentTree?.maxDepth || 7}</span>
          </div>
        </div>

        {/* Right: Feature Importance Bar Chart */}
        <div className="lg:col-span-5 bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-cyan-400" />
                  MDI Feature Importance Ranking
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Mean Decrease in Impurity across all 25 ensemble trees.
                </p>
              </div>
            </div>

            {/* Bars */}
            <div className="space-y-2.5 max-h-[380px] overflow-y-auto pr-1">
              {metrics?.featureImportances.slice(0, 10).map((feat, idx) => {
                const pct = (feat.importance * 100).toFixed(1);
                return (
                  <div key={feat.key} className="space-y-1">
                    <div className="flex justify-between text-xs font-mono">
                      <span className="text-slate-300 font-medium truncate max-w-[200px]">
                        #{idx + 1} {feat.name}
                      </span>
                      <span className="text-cyan-400 font-bold">{pct}%</span>
                    </div>
                    <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800">
                      <div
                        style={{ width: `${Math.min(100, Number(pct) * 8)}%` }}
                        className="bg-gradient-to-r from-cyan-500 to-emerald-400 h-full rounded-full"
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/80 text-[11px] text-slate-400 font-mono">
            Evaluated on Gini Impurity reduction at each split node.
          </div>
        </div>
      </div>

      {/* Hyperparameter Tuner & Retraining Simulator */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              Hyperparameter Tuning & Retraining Engine
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Customize ensemble dimensions, tree depth, and split purity criteria to retrain the forest.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2">
          {/* nEstimators */}
          <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
            <div className="flex justify-between text-xs font-mono mb-1.5">
              <span className="text-slate-300">Number of Trees (n_estimators)</span>
              <span className="text-cyan-400 font-bold">{nEstimators}</span>
            </div>
            <input
              type="range"
              min="5"
              max="50"
              step="5"
              value={nEstimators}
              onChange={(e) => setNEstimators(Number(e.target.value))}
              className="w-full accent-cyan-400 cursor-pointer"
            />
            <div className="flex justify-between text-[10px] text-slate-400 font-mono mt-1">
              <span>5 trees</span>
              <span>50 trees</span>
            </div>
          </div>

          {/* maxDepth */}
          <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
            <div className="flex justify-between text-xs font-mono mb-1.5">
              <span className="text-slate-300">Max Tree Depth (max_depth)</span>
              <span className="text-cyan-400 font-bold">{maxDepth}</span>
            </div>
            <input
              type="range"
              min="3"
              max="12"
              step="1"
              value={maxDepth}
              onChange={(e) => setMaxDepth(Number(e.target.value))}
              className="w-full accent-cyan-400 cursor-pointer"
            />
            <div className="flex justify-between text-[10px] text-slate-400 font-mono mt-1">
              <span>Depth 3</span>
              <span>Depth 12</span>
            </div>
          </div>

          {/* minSamplesSplit */}
          <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
            <div className="flex justify-between text-xs font-mono mb-1.5">
              <span className="text-slate-300">Min Samples Split</span>
              <span className="text-cyan-400 font-bold">{minSamplesSplit}</span>
            </div>
            <input
              type="range"
              min="2"
              max="8"
              step="1"
              value={minSamplesSplit}
              onChange={(e) => setMinSamplesSplit(Number(e.target.value))}
              className="w-full accent-cyan-400 cursor-pointer"
            />
            <div className="flex justify-between text-[10px] text-slate-400 font-mono mt-1">
              <span>2 samples</span>
              <span>8 samples</span>
            </div>
          </div>
        </div>

        {/* Retrain Action */}
        <div className="mt-4 flex flex-col sm:flex-row items-center justify-between gap-3 pt-3 border-t border-slate-800/80">
          <div className="text-xs text-slate-400">
            {retrainSuccessMsg && (
              <span className="text-emerald-400 font-mono flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" />
                {retrainSuccessMsg}
              </span>
            )}
          </div>

          <button
            type="button"
            disabled={isRetraining}
            onClick={handleRetrain}
            className="w-full sm:w-auto bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 text-slate-950 font-bold px-5 py-2 rounded-xl text-xs flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 transition-all cursor-pointer disabled:opacity-50"
          >
            {isRetraining ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Training Forest...</span>
              </>
            ) : (
              <>
                <RefreshCw className="w-4 h-4" />
                <span>Retrain Random Forest</span>
              </>
            )}
          </button>
        </div>
      </div>

    </div>
  );
};
