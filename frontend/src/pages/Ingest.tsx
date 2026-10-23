import React, { useState, useRef, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'sonner';
import './Ingest.css';
import {
  Shield,
  UploadCloud,
  FileArchive,
  ArrowRight,
  ArrowLeft,
  CheckCircle2,
  X,
  Zap,
  GitBranch,
  Lock,
  Globe,
  Search,
  RefreshCw,
  LogOut,
  Check,
  Loader2,
} from 'lucide-react';
import { SecurityGraph3D } from '../components/SecurityGraph3D';
import {
  uploadAndScanArchive,
  scanRepositoryUrl,
  getAuthMe,
  logoutAuth,
  getGithubRepos,
  BACKEND_URL,
  type UserProfile,
  type GitHubRepo,
} from '../services/api';

const GithubIcon: React.FC<{ className?: string }> = ({ className = 'w-4 h-4' }) => (
  <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden="true">
    <path
      fillRule="evenodd"
      clipRule="evenodd"
      d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
    />
  </svg>
);

type IngestionTab = 'github' | 'upload';

interface ScanStep {
  label: string;
  sublabel: string;
}

const scanSteps: ScanStep[] = [
  { label: 'Ingesting repository tree', sublabel: 'Unpacking source structure & dependencies' },
  { label: 'Tree-sitter AST parsing', sublabel: 'Extracting semantic syntax nodes & calls' },
  { label: 'Security rule evaluation', sublabel: 'Matching secret leaks, SQLi & CVEs' },
  { label: 'Synthesizing attack paths', sublabel: 'Computing severity rank & graph linkages' },
];

export const MAX_UPLOAD_SIZE_MB = Number(import.meta.env.VITE_MAX_UPLOAD_SIZE_MB) || 100;
export const MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024;

export const Ingest: React.FC = () => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<IngestionTab>('github');
  const [githubUrl, setGithubUrl] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [currentStepIndex, setCurrentStepIndex] = useState(0);

  // Authentication & GitHub repositories state
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(null);
  const [isLoggingOut, setIsLoggingOut] = useState<boolean>(false);
  const [repos, setRepos] = useState<GitHubRepo[]>([]);
  const [isLoadingRepos, setIsLoadingRepos] = useState<boolean>(false);
  const [reposError, setReposError] = useState<string | null>(null);
  const [repoSearchQuery, setRepoSearchQuery] = useState<string>('');

  const fileInputRef = useRef<HTMLInputElement>(null);

  const sampleRepos = [
    'codeguard-platform/core-api',
    'expressjs/express',
    'vercel/next.js',
  ];

  const isGithubValid = githubUrl.trim().length >= 3;
  const isUploadValid = selectedFile !== null;

  // Enforce zero-scroll full-viewport layout scoped strictly to /ingest
  useEffect(() => {
    document.documentElement.classList.add('ingest-active');
    document.body.classList.add('ingest-active');
    return () => {
      document.documentElement.classList.remove('ingest-active');
      document.body.classList.remove('ingest-active');
    };
  }, []);

  // On mount: check authentication status and load repositories if logged in
  useEffect(() => {
    let isMounted = true;

    async function checkAuthAndLoadRepos() {
      try {
        const authData = await getAuthMe();
        if (!isMounted) return;

        if (authData.authenticated && authData.user) {
          setIsAuthenticated(true);
          setCurrentUser(authData.user);

          // Check for ?connected=github in URL params
          const params = new URLSearchParams(window.location.search);
          if (params.get('connected') === 'github') {
            toast.success(`Connected as ${authData.user.username}`, {
              description: 'You can now select from your public and private repositories.',
              icon: <GithubIcon className="w-4 h-4 text-emerald-400" />,
            });
            // Clean up URL query parameters without reloading the page
            navigate('/ingest', { replace: true });
          }

          // Fetch user's GitHub repositories
          setIsLoadingRepos(true);
          setReposError(null);
          try {
            const userRepos = await getGithubRepos();
            if (isMounted) {
              setRepos(userRepos);
            }
          } catch (repoErr: any) {
            if (isMounted) {
              setReposError(repoErr.message || 'Failed to load repositories');
            }
          } finally {
            if (isMounted) {
              setIsLoadingRepos(false);
            }
          }
        } else {
          setIsAuthenticated(false);
          setCurrentUser(null);
          setRepos([]);
        }
      } catch {
        if (isMounted) {
          setIsAuthenticated(false);
          setCurrentUser(null);
        }
      }
    }

    checkAuthAndLoadRepos();

    return () => {
      isMounted = false;
    };
  }, [navigate]);

  // Full page redirect to initiate GitHub OAuth authorization flow
  const handleGithubOAuthClick = () => {
    window.location.href = `${BACKEND_URL}/api/auth/github`;
  };

  // Disconnect GitHub session
  const handleDisconnect = async () => {
    setIsLoggingOut(true);
    try {
      await logoutAuth();
      setIsAuthenticated(false);
      setCurrentUser(null);
      setRepos([]);
      setGithubUrl('');
      toast.info('Disconnected from GitHub', {
        description: 'Session ended. You can still scan public repositories manually.',
      });
    } catch {
      toast.error('Failed to log out');
    } finally {
      setIsLoggingOut(false);
    }
  };

  // Refresh repository listing
  const handleRefreshRepos = async () => {
    setIsLoadingRepos(true);
    setReposError(null);
    try {
      const userRepos = await getGithubRepos();
      setRepos(userRepos);
      toast.success('Repository list refreshed', {
        description: `Found ${userRepos.length} repositories.`,
      });
    } catch (err: any) {
      setReposError(err.message || 'Failed to refresh repositories');
      toast.error('Failed to refresh repositories');
    } finally {
      setIsLoadingRepos(false);
    }
  };

  // Filtered repositories based on search query
  const filteredRepos = repos.filter((r) => {
    const q = repoSearchQuery.trim().toLowerCase();
    if (!q) return true;
    return (
      r.name.toLowerCase().includes(q) ||
      r.full_name.toLowerCase().includes(q) ||
      (r.description && r.description.toLowerCase().includes(q))
    );
  });

  const formatRepoDate = (dateStr: string) => {
    if (!dateStr) return '';
    try {
      const d = new Date(dateStr);
      if (isNaN(d.getTime())) return '';
      return d.toLocaleDateString(undefined, {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
      });
    } catch {
      return '';
    }
  };

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      if (file.name.endsWith('.zip') || file.type.includes('zip')) {
        if (file.size > MAX_UPLOAD_SIZE_BYTES) {
          toast.error('File size limit exceeded', {
            description: `File size exceeds ${MAX_UPLOAD_SIZE_MB}MB limit (${(file.size / (1024 * 1024)).toFixed(1)} MB).`,
          });
          return;
        }
        setSelectedFile(file);
        toast.success(`Selected ${file.name}`, {
          description: `${(file.size / (1024 * 1024)).toFixed(2)} MB archive ready to analyze.`,
        });
      } else {
        toast.error('Invalid file format', {
          description: 'Please upload a .zip archive containing your codebase.',
        });
      }
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      if (file.size > MAX_UPLOAD_SIZE_BYTES) {
        toast.error('File size limit exceeded', {
          description: `File size exceeds ${MAX_UPLOAD_SIZE_MB}MB limit (${(file.size / (1024 * 1024)).toFixed(1)} MB).`,
        });
        if (fileInputRef.current) {
          fileInputRef.current.value = '';
        }
        return;
      }
      setSelectedFile(file);
      toast.success(`Selected ${file.name}`, {
        description: `${(file.size / (1024 * 1024)).toFixed(2)} MB archive ready to analyze.`,
      });
    }
  };

  const handleGithubSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isGithubValid || isScanning) return;

    const url = githubUrl.trim();
    setIsScanning(true);
    setCurrentStepIndex(0);

    toast.info('Scan initiated', {
      description: `Cloning and analyzing ${url}...`,
      icon: <Zap className="w-4 h-4 text-emerald-400" />,
    });

    // Drive stages 0 -> 1 -> 2 while the network request is in flight
    const stepInterval = setInterval(() => {
      setCurrentStepIndex((prev) => {
        if (prev < 2) {
          return prev + 1;
        }
        return prev;
      });
    }, 450);

    try {
      const scanResult = await scanRepositoryUrl(url);

      clearInterval(stepInterval);
      setCurrentStepIndex(3);

      setTimeout(() => {
        navigate('/dashboard', {
          state: {
            scanCompleted: true,
            isRealScan: true,
            findings: scanResult.findings,
            metadata: scanResult.metadata,
            summary: scanResult.summary,
            graph: scanResult.graph,
            fixes: scanResult.fixes || [],
            agentTrace: scanResult.agentTrace || [],
          },
        });
      }, 400);
    } catch (err: any) {
      clearInterval(stepInterval);
      setIsScanning(false);
      setCurrentStepIndex(0);

      toast.error('Scan failed', {
        description: err.message || 'An unexpected error occurred during repository analysis.',
        duration: 6000,
      });
    }
  };

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isUploadValid || !selectedFile || isScanning) return;

    setIsScanning(true);
    setCurrentStepIndex(0);

    toast.info('Scan initiated', {
      description: `Uploading and analyzing ${selectedFile.name}...`,
      icon: <Zap className="w-4 h-4 text-emerald-400" />,
    });

    // Drive stages 0 -> 1 -> 2 while the network request is in flight
    const stepInterval = setInterval(() => {
      setCurrentStepIndex((prev) => {
        // Hold at step 2 (rule evaluation) while awaiting server response
        if (prev < 2) {
          return prev + 1;
        }
        return prev;
      });
    }, 450);

    try {
      const scanResult = await uploadAndScanArchive(selectedFile);

      clearInterval(stepInterval);
      // Advance to final synthesis step 3
      setCurrentStepIndex(3);

      // Brief visual completion pause so user sees all steps resolve
      setTimeout(() => {
        navigate('/dashboard', {
          state: {
            scanCompleted: true,
            isRealScan: true,
            findings: scanResult.findings,
            metadata: scanResult.metadata,
            summary: scanResult.summary,
            graph: scanResult.graph,
            fixes: scanResult.fixes || [],
            agentTrace: scanResult.agentTrace || [],
          },
        });
      }, 400);
    } catch (err: any) {
      clearInterval(stepInterval);
      setIsScanning(false);
      setCurrentStepIndex(0);

      toast.error('Scan failed', {
        description: err.message || 'An unexpected error occurred during analysis.',
        duration: 5000,
      });
    }
  };

  return (
    <div className="ingest-container h-[100dvh] max-h-[100dvh] flex flex-col bg-[#07080e] text-slate-100 selection:bg-emerald-500/20 selection:text-emerald-300 relative overflow-hidden box-border">
      {/* Subtle Corner Ambient Mesh (Low-opacity, doesn't compete with the form) */}
      <div className="fixed top-0 right-0 w-[450px] h-[450px] opacity-25 pointer-events-none z-0">
        <SecurityGraph3D subtle={true} />
      </div>

      {/* Background Soft Glows */}
      <div className="fixed top-1/4 left-1/4 w-[500px] h-[500px] bg-emerald-600/5 blur-[160px] rounded-full pointer-events-none z-0" />
      <div className="fixed bottom-10 right-1/4 w-[500px] h-[500px] bg-violet-600/5 blur-[160px] rounded-full pointer-events-none z-0" />

      {/* Top Brand Bar with Breadcrumb */}
      <header className="ingest-header shrink-0 border-b border-slate-800/80 bg-[#07080e]/90 backdrop-blur-xl z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-12 sm:h-13 flex items-center justify-between">
          <div className="flex items-center gap-3.5">
            <Link
              to="/"
              className="h-8 w-8 sm:h-9 sm:w-9 rounded-lg bg-gradient-to-br from-emerald-500/20 via-violet-500/10 to-cyan-500/20 border border-emerald-500/30 flex items-center justify-center shadow-[0_0_15px_rgba(16,185,129,0.15)] hover:border-emerald-400 transition-colors"
              title="Return to Overview"
            >
              <Shield className="w-4 h-4 sm:w-5 sm:h-5 text-emerald-400" />
            </Link>
            <div className="flex items-center gap-2">
              <Link to="/" className="font-bold text-slate-100 text-xs sm:text-sm tracking-tight hover:text-white transition-colors">
                CodeGuard
              </Link>
              <span className="text-slate-600">/</span>
              <span className="text-[11px] sm:text-xs text-slate-400 font-mono">New Security Scan</span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Link
              to="/"
              className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 font-mono transition-colors"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Overview</span>
            </Link>
          </div>
        </div>
      </header>

      {/* Main Spacious Form Viewport */}
      <main className="ingest-main relative z-10 flex-1 min-h-0 flex flex-col justify-center items-center px-4 sm:px-6 lg:px-8 py-2 sm:py-3 box-border overflow-hidden">
        <div className="w-full max-w-2xl min-h-0 flex flex-col justify-center gap-2.5 sm:gap-3.5 my-auto">
          {/* Section Eyebrow & Title */}
          <div className="ingest-title-block w-full flex flex-col items-center text-center gap-1 sm:gap-1.5 shrink-0">
            <div className="self-center inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border border-emerald-500/30 bg-emerald-950/20 text-emerald-400 text-[10px] sm:text-[11px] font-mono uppercase tracking-wider">
              <Lock className="w-3 h-3 sm:w-3.5 sm:h-3.5" />
              <span>Codebase Ingestion</span>
            </div>
            <h1 className="ingest-title w-full text-xl sm:text-2xl font-extrabold text-white tracking-tight text-center">
              Select repository to analyze
            </h1>
            <p className="ingest-desc text-xs sm:text-sm text-slate-400 max-w-lg leading-relaxed text-center mx-auto">
              Connect a public GitHub repository or upload a local archive. Analysis runs isolated in memory with full AST inspection.
            </p>
          </div>

          {/* Elevated Spacious Form Card */}
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.25 }}
            className="ingest-card rounded-2xl border border-slate-700/80 bg-[#0c0e17]/95 backdrop-blur-2xl shadow-[0_20px_50px_-10px_rgba(0,0,0,0.8)] p-4 sm:p-6 flex flex-col gap-3 sm:gap-3.5 text-left relative shrink-0"
          >
            {/* Subtle card top glow line */}
            <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-emerald-500/40 to-transparent" />

            {/* Prominent Segmented Tab Switcher */}
            <div className="flex items-center p-1 bg-[#06080f] rounded-xl border border-slate-800">
              <button
                type="button"
                onClick={() => {
                  setActiveTab('github');
                  setSelectedFile(null);
                }}
                className={`ingest-tab-btn flex-1 flex items-center justify-center gap-2 py-2 sm:py-2.5 text-xs sm:text-sm font-medium rounded-lg transition-all duration-150 cursor-pointer ${
                  activeTab === 'github'
                    ? 'bg-gradient-to-r from-[#171b2e] to-[#1d223a] text-white shadow-sm border border-slate-600/70 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <GithubIcon className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-emerald-400" />
                <span>GitHub Repository</span>
              </button>

              <button
                type="button"
                onClick={() => {
                  setActiveTab('upload');
                  setGithubUrl('');
                }}
                className={`ingest-tab-btn flex-1 flex items-center justify-center gap-2 py-2 sm:py-2.5 text-xs sm:text-sm font-medium rounded-lg transition-all duration-150 cursor-pointer ${
                  activeTab === 'upload'
                    ? 'bg-gradient-to-r from-[#171b2e] to-[#1d223a] text-white shadow-sm border border-slate-600/70 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                <UploadCloud className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-violet-400" />
                <span>Upload Codebase (.zip)</span>
              </button>
            </div>

            {/* Tab Form Content */}
            <AnimatePresence mode="wait">
              {activeTab === 'github' ? (
                <motion.form
                  key="github-tab"
                  initial={{ opacity: 0, x: -6 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 6 }}
                  transition={{ duration: 0.15 }}
                  onSubmit={handleGithubSubmit}
                  className="flex flex-col gap-2.5 sm:gap-3"
                >
                  {/* OAuth Header / Logged-in Profile State */}
                  {isAuthenticated && currentUser ? (
                    <div className="w-full flex items-center justify-between p-2.5 sm:p-3 rounded-xl border border-emerald-500/30 bg-[#0d1520]/80">
                      <div className="flex items-center gap-3 min-w-0">
                        {currentUser.avatarUrl ? (
                          <img
                            src={currentUser.avatarUrl}
                            alt={currentUser.username}
                            className="w-8 h-8 rounded-full border border-emerald-500/40 object-cover flex-shrink-0"
                          />
                        ) : (
                          <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-bold text-emerald-400 flex-shrink-0">
                            {currentUser.username.slice(0, 2).toUpperCase()}
                          </div>
                        )}
                        <div className="flex flex-col text-left min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-semibold text-slate-100 truncate">
                              {currentUser.name || currentUser.username}
                            </span>
                            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/50 px-1.5 py-0.5 rounded border border-emerald-500/30 flex-shrink-0">
                              Connected
                            </span>
                          </div>
                          <span className="text-[11px] font-mono text-slate-400 truncate">
                            @{currentUser.username}
                          </span>
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={handleDisconnect}
                        disabled={isLoggingOut}
                        className="inline-flex items-center gap-1.5 text-xs font-mono text-slate-400 hover:text-red-400 hover:bg-red-950/20 px-2.5 py-1.5 rounded-lg border border-slate-800 hover:border-red-500/30 transition-all cursor-pointer flex-shrink-0"
                        title="Disconnect GitHub account"
                      >
                        <LogOut className="w-3.5 h-3.5" />
                        <span>{isLoggingOut ? 'Disconnecting...' : 'Disconnect'}</span>
                      </button>
                    </div>
                  ) : (
                    <button
                      type="button"
                      onClick={handleGithubOAuthClick}
                      className="w-full flex items-center justify-center gap-2 py-2.5 sm:py-3 px-4 rounded-xl border border-slate-700/80 bg-[#121526] hover:bg-[#191c33] hover:border-violet-500/40 text-xs sm:text-sm font-medium text-slate-200 hover:text-white transition-all cursor-pointer shadow-sm group"
                    >
                      <GithubIcon className="w-4 h-4 text-slate-300 group-hover:text-violet-400 transition-colors" />
                      <span>Connect with GitHub (OAuth)</span>
                    </button>
                  )}

                  <div className="relative flex items-center justify-center my-0">
                    <span className="h-px bg-slate-800/90 w-full" />
                    <span className="absolute bg-[#0c0e17] px-3 font-mono text-[10px] uppercase tracking-wider text-slate-500">
                      {isAuthenticated ? 'select repository' : 'or enter repository details'}
                    </span>
                  </div>

                  {/* Main Input Area: Repository Picker when Authenticated, URL Input when Not */}
                  {isAuthenticated ? (
                    <div className="flex flex-col gap-2">
                      <div className="flex items-center justify-between">
                        <label className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-2">
                          <span>Your Repositories</span>
                          {!isLoadingRepos && (
                            <span className="text-[11px] font-mono text-slate-500 lowercase font-normal">
                              ({repos.length} found)
                            </span>
                          )}
                        </label>
                        <button
                          type="button"
                          onClick={handleRefreshRepos}
                          disabled={isLoadingRepos}
                          className="inline-flex items-center gap-1 text-[11px] font-mono text-slate-400 hover:text-emerald-400 transition-colors cursor-pointer"
                          title="Refresh repository list"
                        >
                          <RefreshCw className={`w-3 h-3 ${isLoadingRepos ? 'animate-spin text-emerald-400' : ''}`} />
                          <span>Refresh</span>
                        </button>
                      </div>

                      {/* Search / filter box */}
                      <div className="relative">
                        <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
                        <input
                          type="text"
                          value={repoSearchQuery}
                          onChange={(e) => setRepoSearchQuery(e.target.value)}
                          placeholder="Search repositories (e.g. name, keyword)..."
                          className="w-full pl-10 pr-9 py-2 bg-[#06080f] border border-slate-800 rounded-xl text-xs font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500/60 focus:ring-1 focus:ring-emerald-500/20 transition-all shadow-inner"
                        />
                        {repoSearchQuery && (
                          <button
                            type="button"
                            onClick={() => setRepoSearchQuery('')}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                          >
                            <X className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>

                      {/* Repositories list container */}
                      {isLoadingRepos ? (
                        <div className="p-6 border border-slate-800/80 rounded-xl bg-[#06080f]/50 flex flex-col items-center justify-center gap-2 text-slate-400">
                          <Loader2 className="w-5 h-5 animate-spin text-emerald-400" />
                          <span className="text-xs font-mono">Loading repositories from GitHub...</span>
                        </div>
                      ) : reposError ? (
                        <div className="p-3.5 border border-red-500/30 rounded-xl bg-red-950/20 flex items-center justify-between text-xs font-mono">
                          <span className="text-red-400 truncate max-w-sm">{reposError}</span>
                          <button
                            type="button"
                            onClick={handleRefreshRepos}
                            className="px-2.5 py-1 rounded bg-red-900/40 text-red-200 hover:bg-red-900/60 border border-red-500/40 cursor-pointer"
                          >
                            Retry
                          </button>
                        </div>
                      ) : repos.length === 0 ? (
                        <div className="p-4 border border-slate-800/80 rounded-xl bg-[#06080f]/50 text-center text-xs font-mono text-slate-500">
                          No repositories found on this GitHub account.
                        </div>
                      ) : filteredRepos.length === 0 ? (
                        <div className="p-4 border border-slate-800/80 rounded-xl bg-[#06080f]/50 text-center text-xs font-mono text-slate-500">
                          No repositories match "{repoSearchQuery}".
                        </div>
                      ) : (
                        <div className="max-h-36 sm:max-h-44 overflow-y-auto pr-1 flex flex-col gap-1.5">
                          {filteredRepos.map((repo) => {
                            const isSelected = githubUrl === repo.full_name || githubUrl === repo.html_url;
                            return (
                              <button
                                key={repo.full_name}
                                type="button"
                                onClick={() => setGithubUrl(repo.full_name)}
                                className={`w-full flex items-center justify-between p-2.5 sm:p-3 rounded-xl border text-left transition-all cursor-pointer ${
                                  isSelected
                                    ? 'border-emerald-500/80 bg-emerald-950/30 shadow-[0_0_15px_rgba(16,185,129,0.15)] ring-1 ring-emerald-500/30'
                                    : 'border-slate-800/80 bg-[#06080f]/80 hover:bg-[#0f1322] hover:border-slate-700'
                                }`}
                              >
                                <div className="flex items-center gap-2.5 min-w-0">
                                  <GitBranch
                                    className={`w-4 h-4 flex-shrink-0 ${
                                      isSelected ? 'text-emerald-400' : 'text-slate-500'
                                    }`}
                                  />
                                  <div className="min-w-0">
                                    <div className="flex items-center gap-2">
                                      <span
                                        className={`text-xs font-mono font-medium truncate ${
                                          isSelected ? 'text-emerald-300 font-semibold' : 'text-slate-200'
                                        }`}
                                      >
                                        {repo.full_name}
                                      </span>
                                      {repo.private ? (
                                        <span className="inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-violet-950/50 text-violet-300 border border-violet-500/30 flex-shrink-0">
                                          <Lock className="w-2.5 h-2.5" />
                                          Private
                                        </span>
                                      ) : (
                                        <span className="inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800 flex-shrink-0">
                                          <Globe className="w-2.5 h-2.5" />
                                          Public
                                        </span>
                                      )}
                                    </div>
                                    {repo.description && (
                                      <p className="text-[11px] text-slate-500 truncate max-w-md mt-0.5">
                                        {repo.description}
                                      </p>
                                    )}
                                  </div>
                                </div>

                                <div className="flex items-center gap-2 flex-shrink-0 pl-2">
                                  {repo.updated_at && (
                                    <span className="text-[10px] font-mono text-slate-500 hidden sm:inline">
                                      {formatRepoDate(repo.updated_at)}
                                    </span>
                                  )}
                                  {isSelected ? (
                                    <div className="w-4.5 h-4.5 rounded-full bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
                                      <Check className="w-3 h-3" />
                                    </div>
                                  ) : (
                                    <div className="w-4.5 h-4.5 rounded-full border border-slate-800" />
                                  )}
                                </div>
                              </button>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  ) : (
                    /* When NOT authenticated: manual URL or slug input */
                    <div className="flex flex-col gap-1.5">
                      <label
                        htmlFor="githubUrl"
                        className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono flex items-center justify-between"
                      >
                        <span>Repository URL or Slug</span>
                        <span className="text-[11px] text-slate-500 lowercase font-sans font-normal">e.g. org/repo</span>
                      </label>
                      <div className="relative">
                        <GitBranch className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500" />
                        <input
                          id="githubUrl"
                          type="text"
                          value={githubUrl}
                          onChange={(e) => setGithubUrl(e.target.value)}
                          placeholder="https://github.com/codeguard-platform/core-api"
                          className="w-full pl-10 pr-4 py-2.5 sm:py-3 bg-[#06080f] border border-slate-800 rounded-xl text-xs sm:text-sm font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-emerald-500/60 focus:ring-1 focus:ring-emerald-500/30 transition-all shadow-inner"
                        />
                      </div>
                    </div>
                  )}

                  {/* Selected target preview banner */}
                  {githubUrl && (
                    <div className="flex items-center justify-between px-3 py-1.5 rounded-xl bg-emerald-950/20 border border-emerald-500/30 text-xs font-mono">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="text-slate-400 flex-shrink-0">Target:</span>
                        <span className="text-emerald-300 font-semibold truncate">{githubUrl}</span>
                      </div>
                      <button
                        type="button"
                        onClick={() => setGithubUrl('')}
                        className="text-slate-400 hover:text-red-400 p-0.5 rounded transition-colors flex-shrink-0 cursor-pointer"
                        title="Clear target"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  )}

                  {/* Spaced-Out Sample Chips */}
                  <div className="flex flex-col gap-1.5">
                    <span className="text-[10px] uppercase font-mono tracking-wider text-slate-500">
                      Sample repositories for quick verification:
                    </span>
                    <div className="flex items-center gap-1.5 sm:gap-2 flex-wrap">
                      {sampleRepos.map((repo) => {
                        const isSelected = githubUrl === repo;
                        return (
                          <button
                            key={repo}
                            type="button"
                            onClick={() => setGithubUrl(repo)}
                            className={`px-2.5 py-1 rounded-lg border text-[11px] sm:text-xs font-mono transition-all cursor-pointer ${
                              isSelected
                                ? 'bg-emerald-950/40 border-emerald-500 text-emerald-300 shadow-sm'
                                : 'bg-[#121526] hover:bg-[#1a1f38] border-slate-800 hover:border-violet-500/40 text-emerald-400 hover:text-emerald-300'
                            }`}
                          >
                            {repo}
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {/* Submit Action */}
                  <button
                    type="submit"
                    disabled={!isGithubValid || isScanning}
                    className={`ingest-submit-btn w-full mt-0.5 flex items-center justify-center gap-2 py-2.5 sm:py-3 px-5 rounded-xl text-xs sm:text-sm font-semibold tracking-wide transition-all ${
                      isGithubValid && !isScanning
                        ? 'bg-gradient-to-r from-emerald-500 via-teal-400 to-emerald-500 hover:from-emerald-400 hover:to-teal-300 text-slate-950 shadow-[0_0_24px_rgba(16,185,129,0.35)] cursor-pointer'
                        : 'bg-slate-800/60 text-slate-500 border border-slate-800 cursor-not-allowed'
                    }`}
                  >
                    <span>Run Security Analysis</span>
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </motion.form>
              ) : (
                <motion.form
                  key="upload-tab"
                  initial={{ opacity: 0, x: 6 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -6 }}
                  transition={{ duration: 0.15 }}
                  onSubmit={handleUploadSubmit}
                  className="flex flex-col gap-2.5 sm:gap-3"
                >
                  <input
                    type="file"
                    ref={fileInputRef}
                    onChange={handleFileSelect}
                    accept=".zip"
                    className="hidden"
                  />

                  {/* Drag-and-drop zone */}
                  {!selectedFile ? (
                    <div
                      onDragOver={(e) => {
                        e.preventDefault();
                        setIsDragging(true);
                      }}
                      onDragLeave={() => setIsDragging(false)}
                      onDrop={handleFileDrop}
                      onClick={() => fileInputRef.current?.click()}
                      className={`ingest-dropzone border-2 border-dashed rounded-xl p-4 sm:p-6 lg:p-7 flex flex-col items-center justify-center text-center cursor-pointer transition-all duration-150 ${
                        isDragging
                          ? 'border-emerald-500 bg-emerald-950/20 shadow-[0_0_30px_rgba(16,185,129,0.25)]'
                          : 'border-slate-800 hover:border-slate-700 bg-[#06080f]/80 hover:bg-[#06080f]'
                      }`}
                    >
                      <div className="ingest-dropzone-icon w-10 h-10 sm:w-11 sm:h-11 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-400 mb-2 sm:mb-2.5 group-hover:text-emerald-400 transition-colors shadow-md">
                        <UploadCloud className="w-5 h-5 sm:w-6 sm:h-6" />
                      </div>
                      <p className="text-xs sm:text-sm font-medium text-slate-200">
                        Drag and drop your project <code className="text-emerald-400 font-mono">.zip</code> archive here
                      </p>
                      <p className="text-[10px] sm:text-xs text-slate-500 font-mono mt-1">
                        or click anywhere in this box to browse local storage (max {MAX_UPLOAD_SIZE_MB}MB)
                      </p>
                    </div>
                  ) : (
                    /* Selected file card */
                    <div className="flex items-center justify-between p-3 sm:p-3.5 rounded-xl border border-emerald-500/40 bg-emerald-950/20">
                      <div className="flex items-center gap-3">
                        <div className="w-9 h-9 sm:w-10 sm:h-10 rounded-xl bg-emerald-900/40 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shadow-sm flex-shrink-0">
                          <FileArchive className="w-5 h-5" />
                        </div>
                        <div className="min-w-0">
                          <p className="text-xs sm:text-sm font-semibold text-slate-100 font-mono truncate max-w-xs sm:max-w-sm">
                            {selectedFile.name}
                          </p>
                          <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                            {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB · Codebase Archive Ready
                          </p>
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={() => setSelectedFile(null)}
                        className="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-red-950/30 transition-colors flex-shrink-0"
                        title="Remove file"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                  )}

                  {/* Submit Action */}
                  <button
                    type="submit"
                    disabled={!isUploadValid || isScanning}
                    className={`ingest-submit-btn w-full mt-0.5 flex items-center justify-center gap-2 py-2.5 sm:py-3 px-5 rounded-xl text-xs sm:text-sm font-semibold tracking-wide transition-all ${
                      isUploadValid && !isScanning
                        ? 'bg-gradient-to-r from-emerald-500 via-teal-400 to-emerald-500 hover:from-emerald-400 hover:to-teal-300 text-slate-950 shadow-[0_0_24px_rgba(16,185,129,0.35)] cursor-pointer'
                        : 'bg-slate-800/60 text-slate-500 border border-slate-800 cursor-not-allowed'
                    }`}
                  >
                    <span>Analyze Uploaded Archive</span>
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </motion.form>
              )}
            </AnimatePresence>
          </motion.div>

          {/* Privacy & Assurance Footer */}
          <div className="ingest-footer flex items-center justify-center gap-5 sm:gap-6 text-[10px] sm:text-xs font-mono text-slate-500 shrink-0">
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" /> Ephemeral AST analysis
            </span>
            <span className="flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" /> Never stored on disk
            </span>
          </div>
        </div>
      </main>

      {/* Scanning Progress Modal Overlay */}
      <AnimatePresence>
        {isScanning && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/85 backdrop-blur-md z-50 flex items-center justify-center p-4"
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="w-full max-w-md p-6 rounded-2xl border border-slate-800 bg-[#0c0e17] shadow-2xl flex flex-col gap-5 text-left"
            >
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-emerald-950/60 to-violet-950/40 border border-emerald-500/40 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-emerald-400 animate-pulse" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-slate-100">Analyzing Codebase</h3>
                  <p className="text-xs text-slate-400 font-mono">AST Heuristics & Attack Synthesizer</p>
                </div>
              </div>

              {/* Steps list */}
              <div className="flex flex-col gap-3 py-2">
                {scanSteps.map((step, idx) => {
                  const isDone = idx < currentStepIndex;
                  const isCurrent = idx === currentStepIndex;

                  return (
                    <div key={idx} className="flex items-start gap-3">
                      <div className="mt-0.5">
                        {isDone ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        ) : isCurrent ? (
                          <span className="flex h-4 w-4 relative items-center justify-center">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-violet-400 opacity-75" />
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-violet-400" />
                          </span>
                        ) : (
                          <span className="w-4 h-4 rounded-full border border-slate-700 block" />
                        )}
                      </div>
                      <div className="min-w-0">
                        <p
                          className={`text-xs font-medium ${
                            isCurrent
                              ? 'text-white font-semibold'
                              : isDone
                              ? 'text-slate-300'
                              : 'text-slate-500'
                          }`}
                        >
                          {step.label}
                        </p>
                        <p className="text-[11px] text-slate-500 font-mono">{step.sublabel}</p>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Progress Bar with Dual-Tone Gradient */}
              <div className="w-full h-1.5 bg-slate-900 rounded-full overflow-hidden border border-slate-800">
                <motion.div
                  className="h-full bg-gradient-to-r from-emerald-500 via-teal-400 to-violet-500"
                  initial={{ width: '10%' }}
                  animate={{
                    width: `${Math.min(((currentStepIndex + 1) / scanSteps.length) * 100, 100)}%`,
                  }}
                  transition={{ duration: 0.35 }}
                />
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};
