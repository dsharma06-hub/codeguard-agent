import React from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Shield,
  ArrowRight,
  Sparkles,
  Lock,
  Network,
  Cpu,
  Layers,
} from 'lucide-react';
import { SecurityGraph3D } from '../components/SecurityGraph3D';

export const Landing: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="relative min-h-screen flex flex-col bg-[#07080e] text-slate-100 overflow-x-hidden selection:bg-emerald-500/20 selection:text-emerald-300">
      {/* 1. Full-Bleed 3D Attack-Path Mesh Background (Spans 100% of the viewport) */}
      <div className="fixed inset-0 z-0 pointer-events-none overflow-hidden">
        <SecurityGraph3D className="w-full h-full opacity-100" />
      </div>

      {/* 2. Soft Edge Gradient Vignette */}
      <div className="fixed inset-0 z-0 pointer-events-none bg-[radial-gradient(ellipse_at_center,_transparent_40%,_rgba(7,8,14,0.35)_80%,_rgba(7,8,14,0.65)_100%)]" />

      {/* Ambient Multi-Hue Color Blobs */}
      <div className="fixed top-1/4 -left-20 w-[600px] h-[500px] bg-emerald-600/15 blur-[180px] rounded-full pointer-events-none z-0" />
      <div className="fixed bottom-1/4 -right-20 w-[600px] h-[500px] bg-violet-600/15 blur-[180px] rounded-full pointer-events-none z-0" />

      {/* Main Hero Viewport (No header bar on "/" — page starts directly with 3D scene & hero content) */}
      <main className="relative z-10 flex-1 flex flex-col justify-center items-center text-center px-4 sm:px-6 lg:px-8 pt-20 sm:pt-28 pb-16 sm:pb-20 max-w-5xl mx-auto min-h-[calc(100vh-50px)]">
        {/* Localized Text Contrast Shield: Softens mesh lines directly behind typography while leaving surrounding scene 100% vibrant */}
        <div
          className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[780px] max-w-[94vw] h-[480px] -z-10 pointer-events-none rounded-full bg-[radial-gradient(ellipse_at_center,_rgba(7,8,14,0.85)_0%,_rgba(7,8,14,0.6)_45%,_rgba(7,8,14,0)_75%)] backdrop-blur-[2px]"
          aria-hidden="true"
        />

        {/* Brand Identity Mark inside Hero Content */}
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25 }}
          className="inline-flex items-center gap-3 mb-6 px-4 py-2 rounded-2xl bg-[#0c0e17]/70 border border-white/10 shadow-[0_4px_24px_rgba(0,0,0,0.6)] backdrop-blur-md"
        >
          <div className="h-8 w-8 rounded-lg bg-gradient-to-br from-emerald-500/20 via-violet-500/10 to-cyan-500/20 border border-emerald-500/40 flex items-center justify-center shadow-[0_0_15px_rgba(16,185,129,0.25)]">
            <Shield className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-center gap-2">
            <span className="font-extrabold text-slate-100 text-sm tracking-tight drop-shadow-sm">
              CodeGuard
            </span>
            <span className="text-slate-600">/</span>
            <span className="text-[11px] text-slate-300 font-mono uppercase tracking-wider drop-shadow-sm">
              Static Security & Attack Graph Engine
            </span>
          </div>
        </motion.div>

        {/* Eyebrow Pill */}
        <motion.div
          initial={{ opacity: 0, y: -6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25, delay: 0.05 }}
          className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full border border-violet-500/40 bg-violet-950/30 text-violet-200 text-xs font-mono uppercase tracking-wider mb-6 shadow-[0_0_18px_rgba(139,92,246,0.2)] backdrop-blur-md"
        >
          <Lock className="w-3.5 h-3.5 text-emerald-400" />
          <span>AST Security Engine</span>
          <span className="text-slate-600">·</span>
          <span className="text-emerald-400 font-sans font-medium lowercase">v0.1.0-alpha</span>
        </motion.div>

        {/* Dominant Headline (5xl - 7xl) with High-Contrast Luminous Text */}
        <motion.h1
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.08 }}
          className="text-4xl sm:text-6xl lg:text-7xl font-extrabold tracking-[-0.04em] leading-[1.05] text-white max-w-4xl drop-shadow-[0_4px_30px_rgba(0,0,0,0.98)]"
        >
          Find critical security flaws{' '}
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-300 via-teal-200 to-indigo-300 drop-shadow-[0_2px_14px_rgba(0,0,0,0.9)]">
            before your code ships.
          </span>
        </motion.h1>

        {/* Subheadline with generous line-height */}
        <motion.p
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.12 }}
          className="text-base sm:text-lg lg:text-xl text-slate-300 font-normal leading-relaxed max-w-2xl mt-6 font-sans text-balance drop-shadow-[0_2px_18px_rgba(0,0,0,0.95)]"
        >
          CodeGuard statically traces hardcoded secrets, injection patterns, vulnerable dependencies,
          and AI-generated antipatterns into an actionable, severity-ranked attack-path graph.
        </motion.p>

        {/* Single Primary CTA Button */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.16 }}
          className="flex flex-col sm:flex-row items-center gap-3.5 mt-8 w-full sm:w-auto"
        >
          <button
            onClick={() => navigate('/ingest')}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2.5 px-7 py-3.5 rounded-xl text-sm font-semibold tracking-wide bg-gradient-to-r from-emerald-500 via-teal-400 to-emerald-500 hover:from-emerald-400 hover:to-teal-300 text-slate-950 shadow-[0_0_28px_rgba(16,185,129,0.35)] hover:shadow-[0_0_36px_rgba(16,185,129,0.5)] transition-all transform hover:-translate-y-0.5 cursor-pointer"
          >
            <span>Start Security Scan</span>
            <ArrowRight className="w-4 h-4" />
          </button>

          <button
            onClick={() => navigate('/dashboard')}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-5 py-3.5 rounded-xl text-sm font-medium text-slate-200 hover:text-white bg-[#0f121e]/80 hover:bg-[#161a2c] border border-slate-700/80 transition-all cursor-pointer backdrop-blur-md shadow-sm"
          >
            <Sparkles className="w-4 h-4 text-violet-400" />
            <span>Explore Sample Dashboard</span>
          </button>
        </motion.div>

        {/* Bottom Capabilities Strip */}
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.2 }}
          className="grid grid-cols-1 sm:grid-cols-3 gap-3 w-full max-w-3xl mt-16 text-left"
        >
          <div className="p-4 rounded-xl border border-slate-800/80 bg-[#0c0e17]/80 backdrop-blur-xl shadow-lg flex flex-col gap-1.5">
            <div className="flex items-center gap-2 text-xs font-mono font-semibold text-emerald-400">
              <Cpu className="w-4 h-4" />
              <span>Tree-sitter AST</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed font-sans">
              Structural abstract syntax tree parsing across multi-language repos. No regex false alarms.
            </p>
          </div>

          <div className="p-4 rounded-xl border border-slate-800/80 bg-[#0c0e17]/80 backdrop-blur-xl shadow-lg flex flex-col gap-1.5">
            <div className="flex items-center gap-2 text-xs font-mono font-semibold text-violet-400">
              <Network className="w-4 h-4" />
              <span>Attack-Path Synthesis</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed font-sans">
              Dynamic dependency and taint graph visualization showing exploit vectors from source to sink.
            </p>
          </div>

          <div className="p-4 rounded-xl border border-slate-800/80 bg-[#0c0e17]/80 backdrop-blur-xl shadow-lg flex flex-col gap-1.5">
            <div className="flex items-center gap-2 text-xs font-mono font-semibold text-cyan-400">
              <Layers className="w-4 h-4" />
              <span>Zero Code Retention</span>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed font-sans">
              Instant in-memory processing. Codebase archives are evaluated and purged immediately.
            </p>
          </div>
        </motion.div>
      </main>

      {/* Subtle Footer */}
      <footer className="relative z-10 border-t border-white/10 bg-transparent py-4 text-center text-xs text-slate-500 font-mono">
        <span>CodeGuard Static Security Platform · Confidential Capstone Project</span>
      </footer>
    </div>
  );
};
