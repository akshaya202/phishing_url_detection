import { useEffect, useMemo, useState } from 'react';
import { Link, Route, Routes } from 'react-router-dom';
import axios from 'axios';
import { Activity, AlertTriangle, BarChart3, Bot, Check, CheckCircle2, Eye, EyeOff, FileText, Globe2, KeyRound, Lock, Network, ScanLine, SearchCheck, Shield, ShieldAlert, Settings, TriangleAlert, UserCircle2, ChartNoAxesCombined, X } from 'lucide-react';
import { BarChart, Bar, CartesianGrid, PieChart, Pie, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

const API_BASE = 'http://localhost:8000';
const statusColors = {
  Legitimate: 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30',
  Phishing: 'bg-rose-500/15 text-rose-300 border border-rose-500/30',
  Suspicious: 'bg-amber-500/15 text-amber-300 border border-amber-500/30',
};

const pieColors = ['#34d399', '#f87171', '#fbbf24'];

const normalizePrediction = (prediction) => {
  const value = String(prediction || '').trim().toLowerCase();
  if (value === 'phishing' || value === 'malicious') return 'phishing';
  if (value === 'suspicious') return 'suspicious';
  if (value === 'safe' || value === 'legitimate') return 'safe';
  if (!value) return 'safe';
  return value;
};

const formatRisk = (value) => {
  if (value >= 0.8) return 'High';
  if (value >= 0.5) return 'Medium';
  return 'Low';
};

const buildAuthHeader = (token) => ({ headers: { Authorization: `Bearer ${token}` } });

const SAMPLE_HISTORY = [
  {
    id: 1,
    url: 'https://www.google.com',
    prediction: 'Legitimate',
    confidence: 0.95,
    risk: 0.05,
    reason: 'The URL structure and indicators are consistent with a legitimate web destination.',
    created_at: new Date(Date.now() - 3600000 * 2).toISOString(),
  },
  {
    id: 2,
    url: 'http://paypal-security-verify.xyz/login',
    prediction: 'Phishing',
    confidence: 0.92,
    risk: 0.92,
    reason: 'The URL shows strong phishing indicators such as suspicious domains, malicious keywords, or a high-risk structure.',
    created_at: new Date(Date.now() - 3600000 * 5).toISOString(),
  },
  {
    id: 3,
    url: 'https://github.com/microsoft/vscode',
    prediction: 'Legitimate',
    confidence: 0.97,
    risk: 0.03,
    reason: 'The URL structure and indicators are consistent with a legitimate web destination.',
    created_at: new Date(Date.now() - 3600000 * 8).toISOString(),
  },
  {
    id: 4,
    url: 'https://secure-bankofamerica.xyz/account/update',
    prediction: 'Phishing',
    confidence: 0.88,
    risk: 0.88,
    reason: 'The URL shows strong phishing indicators such as suspicious domains, malicious keywords, or a high-risk structure.',
    created_at: new Date(Date.now() - 3600000 * 12).toISOString(),
  },
  {
    id: 5,
    url: 'https://docs.python.org/3/library/urllib.html',
    prediction: 'Legitimate',
    confidence: 0.98,
    risk: 0.02,
    reason: 'The URL structure and indicators are consistent with a legitimate web destination.',
    created_at: new Date(Date.now() - 3600000 * 18).toISOString(),
  },
  {
    id: 6,
    url: 'http://appleid-verify-account.top/signin',
    prediction: 'Suspicious',
    confidence: 0.62,
    risk: 0.62,
    reason: 'The URL is ambiguous and should be treated cautiously pending additional review.',
    created_at: new Date(Date.now() - 3600000 * 24).toISOString(),
  },
  {
    id: 7,
    url: 'https://www.microsoft.com/en-us/download',
    prediction: 'Legitimate',
    confidence: 0.96,
    risk: 0.04,
    reason: 'The URL structure and indicators are consistent with a legitimate web destination.',
    created_at: new Date(Date.now() - 3600000 * 30).toISOString(),
  },
  {
    id: 8,
    url: 'http://login.netflix.com.verify-account.ga/billing',
    prediction: 'Phishing',
    confidence: 0.85,
    risk: 0.85,
    reason: 'The URL shows strong phishing indicators such as suspicious domains, malicious keywords, or a high-risk structure.',
    created_at: new Date(Date.now() - 3600000 * 36).toISOString(),
  },
];

const getStatusBadge = (prediction) => {
  const normalized = normalizePrediction(prediction);
  if (normalized === 'phishing') return 'bg-rose-500/15 text-rose-300 border border-rose-500/30';
  if (normalized === 'suspicious') return 'bg-amber-500/15 text-amber-300 border border-amber-500/30';
  return 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30';
};

const getStatusLabel = (prediction) => {
  const normalized = normalizePrediction(prediction);
  if (normalized === 'phishing') return 'PHISHING';
  if (normalized === 'suspicious') return 'SUSPICIOUS';
  return 'SAFE';
};

const getRiskColor = (risk) => {
  const score = Number(risk || 0);
  if (score >= 0.8) return 'bg-rose-500';
  if (score >= 0.5) return 'bg-amber-500';
  return 'bg-emerald-500';
};

function SplashScreen({ isExiting }) {
  const particles = [
    { cx: '17%', cy: '34%', delay: '0.1s', size: 2 },
    { cx: '27%', cy: '62%', delay: '0.8s', size: 1.5 },
    { cx: '32%', cy: '25%', delay: '1.2s', size: 1.5 },
    { cx: '72%', cy: '29%', delay: '0.4s', size: 2 },
    { cx: '82%', cy: '48%', delay: '1.1s', size: 1.5 },
    { cx: '73%', cy: '70%', delay: '0.7s', size: 2 },
    { cx: '39%', cy: '79%', delay: '1.5s', size: 1.5 },
    { cx: '61%', cy: '18%', delay: '0.2s', size: 1.5 },
  ];

  return (
    <div className={`splash-screen${isExiting ? ' splash-screen--exiting' : ''}`} aria-label="Loading PhishSense" role="status">
      <div className="splash-halo" />
      <div className="splash-icon-shell">
        <svg className="splash-art" viewBox="0 0 320 320" aria-hidden="true">
          <defs>
            <filter id="splash-glow" x="-80%" y="-80%" width="260%" height="260%">
              <feGaussianBlur stdDeviation="5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <linearGradient id="splash-shield-gradient" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0" stopColor="#a5f3fc" />
              <stop offset="0.45" stopColor="#22d3ee" />
              <stop offset="1" stopColor="#0891b2" />
            </linearGradient>
          </defs>

          <ellipse className="splash-energy-ring splash-energy-ring--outer" cx="160" cy="160" rx="107" ry="67" />
          <ellipse className="splash-energy-ring splash-energy-ring--inner" cx="160" cy="160" rx="91" ry="119" />
          <path
            className="splash-shield"
            d="M160 66 L229 92 V150 C229 197 200 232 160 254 C120 232 91 197 91 150 V92 Z"
            fill="rgba(8, 145, 178, 0.12)"
            stroke="url(#splash-shield-gradient)"
            strokeWidth="5"
            strokeLinejoin="round"
            filter="url(#splash-glow)"
          />
          <path className="splash-shield-check" d="M126 158 L149 181 L197 130" fill="none" stroke="#b6f7ff" strokeWidth="7" strokeLinecap="round" strokeLinejoin="round" />
          {particles.map((particle) => (
            <circle
              key={`${particle.cx}-${particle.cy}`}
              className="splash-particle"
              cx={particle.cx}
              cy={particle.cy}
              r={particle.size}
              style={{ animationDelay: particle.delay }}
            />
          ))}
        </svg>
      </div>
      <p className="splash-label">PhishSense</p>
      <span className="splash-status">SECURE URL INTELLIGENCE</span>
    </div>
  );
}

function App() {
  const [showSplash, setShowSplash] = useState(true);
  const [isSplashExiting, setIsSplashExiting] = useState(false);
  const [token, setToken] = useState(() => localStorage.getItem('token') || sessionStorage.getItem('token') || '');
  const [user, setUser] = useState(() => JSON.parse(localStorage.getItem('user') || sessionStorage.getItem('user') || 'null'));
  const [scanResult, setScanResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [authMode, setAuthMode] = useState('login');
  const [authForm, setAuthForm] = useState({ name: '', email: '', password: '', confirmPassword: '' });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [passwordError, setPasswordError] = useState('');
  const [rememberMe, setRememberMe] = useState(() => localStorage.getItem('rememberMe') !== 'false');
  const [reportUrl, setReportUrl] = useState('');
  const [reportReason, setReportReason] = useState('Phishing');
  const [reportDescription, setReportDescription] = useState('');
  const [scanInput, setScanInput] = useState('');
  const [filterStatus, setFilterStatus] = useState('All Status');
  const [resultAnimationKey, setResultAnimationKey] = useState(0);
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState({
    counts: { legitimate: 0, phishing: 0, suspicious: 0 },
    reports: { total: 0, pending: 0, verified: 0 },
    model: { accuracy: 0, precision: 0, recall: 0, f1: 0 },
    dailyScans: [],
    modelVersion: 'n/a',
  });

  const isAuthenticated = Boolean(token && user);

  useEffect(() => {
    const exitTimer = setTimeout(() => setIsSplashExiting(true), 2400);
    const completeTimer = setTimeout(() => setShowSplash(false), 2900);

    return () => {
      clearTimeout(exitTimer);
      clearTimeout(completeTimer);
    };
  }, []);

  const clearSession = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('rememberMe');
    sessionStorage.removeItem('token');
    sessionStorage.removeItem('user');
    setToken('');
    setUser(null);
    setScanResult(null);
    setHistory([]);
    setStats({
      counts: { legitimate: 0, phishing: 0, suspicious: 0 },
      reports: { total: 0, pending: 0, verified: 0 },
      model: { accuracy: 0, precision: 0, recall: 0, f1: 0 },
      dailyScans: [],
      modelVersion: 'n/a',
    });
    setScanInput('');
    setReportUrl('');
    setReportReason('Phishing');
    setReportDescription('');
    setFilterStatus('All Status');
    setAuthMode('login');
  };

  useEffect(() => {
    const storedToken = localStorage.getItem('token') || sessionStorage.getItem('token') || '';
    const storedUser = JSON.parse(localStorage.getItem('user') || sessionStorage.getItem('user') || 'null');

    if (!storedToken || !storedUser) {
      clearSession();
      return;
    }

    setToken(storedToken);
    setUser(storedUser);
  }, []);

  useEffect(() => {
    localStorage.removeItem('token');
    sessionStorage.removeItem('token');
    if (token) (rememberMe ? localStorage : sessionStorage).setItem('token', token);
  }, [token, rememberMe]);

  useEffect(() => {
    localStorage.removeItem('user');
    sessionStorage.removeItem('user');
    if (user) (rememberMe ? localStorage : sessionStorage).setItem('user', JSON.stringify(user));
  }, [user, rememberMe]);

  useEffect(() => {
    localStorage.setItem('rememberMe', String(rememberMe));
  }, [rememberMe]);

  useEffect(() => {
    if (token) {
      fetchHistory();
      fetchStats();
    }
  }, [token]);

  const fetchHistory = async () => {
    if (!token) return;
    try {
      const res = await axios.get(`${API_BASE}/api/scans/history`, buildAuthHeader(token));
      setHistory(res.data.history || []);
    } catch (error) {
      console.error('History load failed', error);
    }
  };

  const fetchStats = async () => {
    if (!token) return;
    try {
      const res = await axios.get(`${API_BASE}/api/dashboard/summary`, buildAuthHeader(token));
      setStats(res.data);
    } catch (error) {
      console.error('Stats load failed', error);
    }
  };

  const handleAuth = async (e) => {
    e.preventDefault();

    if (authMode === 'register') {
      if (!authForm.password || !authForm.confirmPassword) {
        setPasswordError('Password and Confirm Password are required.');
        return;
      }
      if (authForm.password !== authForm.confirmPassword) {
        setPasswordError('Passwords do not match.');
        return;
      }
    }

    const payload = authMode === 'register'
      ? { name: authForm.name, email: authForm.email, password: authForm.password }
      : { email: authForm.email, password: authForm.password };

    try {
      const endpoint = authMode === 'register' ? '/api/auth/register' : '/api/auth/login';
      const res = await axios.post(`${API_BASE}${endpoint}`, payload);
      setToken(res.data.token);
      setUser(res.data.user);
      setRememberMe(authMode === 'register' ? true : rememberMe);
      setAuthForm({ name: '', email: '', password: '', confirmPassword: '' });
      setPasswordError('');
    } catch (error) {
      alert(error.response?.data?.detail || 'Authentication failed');
    }
  };

  const handleScanFromInput = async () => {
    if (!scanInput.trim()) return;
    await handleScan(scanInput.trim());
  };

  const handleScan = async (url) => {
    if (!url) return;
    setLoading(true);
    try {
      const res = await axios.post(`${API_BASE}/api/scan`, { url }, token ? buildAuthHeader(token) : undefined);
      const result = {
        id: Date.now(),
        url: res.data.url,
        prediction: normalizePrediction(res.data.prediction),
        confidence: Number(res.data.confidence ?? 0),
        risk: Number(res.data.risk ?? 0),
        reason: res.data.reason,
        created_at: new Date().toISOString(),
        model_version: res.data.model_version || stats.modelVersion || 'n/a',
      };
      setScanResult(result);
      setResultAnimationKey((prev) => prev + 1);
      setScanInput('');
      setHistory((prev) => [result, ...prev]);
      if (token) fetchHistory();
    } catch (error) {
      alert(error.response?.data?.detail || 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  const handleReport = async () => {
    const cleanedUrl = reportUrl.trim();
    if (!cleanedUrl) {
      alert('Please enter a URL to report.');
      return;
    }

    try {
      new URL(cleanedUrl.startsWith('http') ? cleanedUrl : `https://${cleanedUrl}`);
    } catch {
      alert('Please enter a valid URL.');
      return;
    }

    if (!token) {
      alert('Please sign in to report a URL.');
      return;
    }

    try {
      await axios.post(
        `${API_BASE}/api/reports`,
        { url: cleanedUrl, reason: reportReason, description: reportDescription.trim() },
        buildAuthHeader(token),
      );
      alert('URL reported successfully.');
      setReportUrl('');
      setReportReason('Phishing');
      setReportDescription('');
      fetchStats();
    } catch (error) {
      alert(error.response?.data?.detail || 'Report submission failed.');
    }
  };

  const threatDistribution = useMemo(() => [
    { name: 'Legitimate', value: stats.counts.legitimate },
    { name: 'Phishing', value: stats.counts.phishing },
    { name: 'Suspicious', value: stats.counts.suspicious },
  ], [stats]);

  const totalScanned = history.length;
  const flaggedPhishing = history.filter((h) => normalizePrediction(h.prediction) === 'phishing').length;
  const verifiedSafe = history.filter((h) => normalizePrediction(h.prediction) === 'safe').length;
  const threatsBlocked = history.filter((h) => ['phishing', 'suspicious'].includes(normalizePrediction(h.prediction))).length;

  const filteredHistory = useMemo(() => {
    if (filterStatus === 'All Status') return history;
    if (filterStatus === 'Phishing') return history.filter((h) => normalizePrediction(h.prediction) === 'phishing');
    if (filterStatus === 'Suspicious') return history.filter((h) => normalizePrediction(h.prediction) === 'suspicious');
    if (filterStatus === 'Safe') return history.filter((h) => normalizePrediction(h.prediction) === 'safe');
    return history;
  }, [history, filterStatus]);

  const resultStatus = scanResult ? normalizePrediction(scanResult.prediction) : 'safe';
  const resultMeta = {
    safe: { title: 'Safe URL', icon: Check, tone: 'safe', badge: 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30' },
    suspicious: { title: 'Suspicious URL', icon: TriangleAlert, tone: 'suspicious', badge: 'bg-amber-500/15 text-amber-300 border border-amber-500/30' },
    phishing: { title: 'Phishing URL Detected', icon: X, tone: 'phishing', badge: 'bg-rose-500/15 text-rose-300 border border-rose-500/30' },
  };
  const currentResultMeta = resultMeta[resultStatus] || resultMeta.safe;

  if (showSplash) {
    return <SplashScreen isExiting={isSplashExiting} />;
  }

  return (
    <div className="min-h-screen text-slate-100">
      {/* Top Navigation Bar */}
      <header className="border-b border-slate-800 bg-slate-950/90 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-cyan-500/15 p-2 text-cyan-300"><Shield /></div>
            <div>
              <p className="text-lg font-semibold">PhishSense</p>
              <p className="text-xs text-slate-400">Dynamic Phishing URL Detection System</p>
            </div>
          </div>

          <div className="hidden items-center gap-6 text-sm md:flex">
            <Link to="/" className="hover:text-white">Home</Link>
            {isAuthenticated && <a href="#report-url" className="hover:text-white">Report URL</a>}
          </div>

          <div className="flex items-center gap-3">
            {user ? (
              <>
                <button className="btn-secondary flex items-center gap-2" aria-label={`Signed in as ${user.name || 'User'}`}>
                  <UserCircle2 size={16} />
                  <span className="hidden max-w-32 truncate md:inline">{user.name || 'User'}</span>
                </button>
                <button className="rounded-xl border border-slate-700 bg-slate-900 p-2 text-slate-300 transition hover:border-slate-500 hover:text-white">
                  <Settings size={18} />
                </button>
                <button className="btn-secondary" onClick={() => { setToken(''); setUser(null); }}>Logout</button>
              </>
            ) : null}
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-8">
        <Routes>
          <Route path="/" element={
            isAuthenticated ? (
              <div className="space-y-8">
                <section className="card p-6 md:p-8">
                    <div className="mb-6 flex items-center gap-3">
                      <div className="rounded-xl bg-cyan-500/10 p-2 text-cyan-300"><Activity /></div>
                      <div>
                        <h1 className="text-2xl font-bold text-white md:text-3xl">Dynamic Phishing URL Detection</h1>
                        <p className="text-sm text-slate-400">Scan URLs with a Random Forest model backed by verified threat intelligence.</p>
                      </div>
                    </div>

                    <div className="flex flex-col gap-4 md:flex-row">
                      <input
                        className="input flex-1 text-base"
                        placeholder="Enter URL to Scan..."
                        value={scanInput}
                        onChange={(e) => {
                          setScanInput(e.target.value);
                          setScanResult(null);
                        }}
                        onKeyDown={(e) => e.key === 'Enter' && handleScanFromInput()}
                      />
                      <button className="btn-primary px-8 py-4 text-base" onClick={handleScanFromInput} disabled={loading}>
                        {loading ? 'Scanning...' : 'Scan URL'}
                      </button>
                    </div>

                    {scanResult && (
                      <div key={resultAnimationKey} className="mt-6 rounded-2xl border border-slate-700 bg-slate-950/80 p-5">
                        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                          <div className="flex items-center gap-4">
                            <div className={`result-visual result-visual--${currentResultMeta.tone}`}>
                              <span className="result-ring" />
                              <currentResultMeta.icon className="result-icon" size={36} strokeWidth={3} />
                            </div>
                            <div>
                              <p className="text-xs uppercase tracking-[0.18em] text-slate-400">Latest Scan Result</p>
                              <h3 className="mt-2 text-2xl font-bold text-white">{currentResultMeta.title}</h3>
                              <p className="mt-1 text-sm text-slate-400 break-all">{scanResult.url}</p>
                            </div>
                          </div>
                          <span className={`badge ${currentResultMeta.badge}`}>
                            {resultStatus === 'safe' ? 'Safe' : resultStatus === 'suspicious' ? 'Suspicious' : 'Phishing'}
                          </span>
                        </div>

                        <div className="mt-6 grid gap-4 md:grid-cols-1">
                          <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
                            <p className="text-xs text-slate-400">Risk Score</p>
                            <p className="mt-2 text-2xl font-bold text-amber-300">{Number(scanResult.risk * 100).toFixed(2)}%</p>
                          </div>
                        </div>

                        <div className="mt-6 rounded-xl border border-slate-700 bg-slate-900 p-4 text-sm text-slate-300">
                          <p className="font-medium text-white">Assessment</p>
                          <p className="mt-2">{scanResult.reason}</p>
                        </div>
                      </div>
                    )}
                </section>

                <section className="space-y-5">
                  <div className="flex items-end justify-between gap-4">
                    <div>
                      <p className="section-kicker">Live telemetry</p>
                      <h2 className="mt-1 text-2xl font-semibold text-white">Security Overview</h2>
                    </div>
                    <span className="hidden items-center gap-2 text-xs text-slate-500 sm:flex"><span className="status-dot" /> Updated from connected scan data</span>
                  </div>
                  <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                    {[
                      { label: 'URLs Scanned', value: totalScanned, icon: ScanLine, tone: 'cyan', detail: 'Total analysis requests' },
                      { label: 'Phishing Detected', value: flaggedPhishing, icon: ShieldAlert, tone: 'rose', detail: 'High-risk URLs flagged' },
                      { label: 'Safe URLs', value: verifiedSafe, icon: CheckCircle2, tone: 'emerald', detail: 'Low-risk destinations' },
                      { label: 'Threats Blocked', value: threatsBlocked, icon: Lock, tone: 'amber', detail: 'Phishing and suspicious' },
                    ].map(({ label, value, icon: Icon, tone, detail }) => (
                      <div key={label} className="metric-card card p-5">
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <p className="text-sm text-slate-400">{label}</p>
                            <p className="mt-3 text-3xl font-bold tracking-tight text-white">{value}</p>
                          </div>
                          <div className={`metric-icon metric-icon--${tone}`}><Icon size={19} /></div>
                        </div>
                        <p className="mt-4 text-xs text-slate-500">{detail}</p>
                      </div>
                    ))}
                  </div>
                </section>

                <section className="grid gap-6 xl:grid-cols-[1.35fr_0.65fr]">
                  <div>
                    <p className="section-kicker">Layered defense</p>
                    <h2 className="mt-1 text-2xl font-semibold text-white">How PhishSense Protects You</h2>
                    <div className="mt-5 grid gap-4 sm:grid-cols-2">
                      {[
                        { icon: SearchCheck, title: 'URL Analysis', text: 'Inspects structure, length, redirects, and patterns that often signal abuse.' },
                        { icon: Bot, title: 'Machine Learning Detection', text: 'Scores each URL against learned phishing and legitimate URL behavior.' },
                        { icon: Globe2, title: 'Domain & Reputation Check', text: 'Looks for suspicious domains, risky TLDs, IP addresses, and reputation signals.' },
                        { icon: KeyRound, title: 'SSL/TLS Security Check', text: 'Checks HTTPS usage and certificate signals that support a safer destination.' },
                      ].map(({ icon: Icon, title, text }) => (
                        <div key={title} className="feature-card card p-5">
                          <div className="feature-icon"><Icon size={19} /></div>
                          <h3 className="mt-4 font-semibold text-white">{title}</h3>
                          <p className="mt-2 text-sm leading-6 text-slate-400">{text}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="card p-5 xl:mt-8">
                    <div className="flex items-center gap-3">
                      <div className="feature-icon"><Network size={19} /></div>
                      <div>
                        <p className="section-kicker">Inspection layers</p>
                        <h3 className="mt-1 text-lg font-semibold text-white">What We Check</h3>
                      </div>
                    </div>
                    <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-1">
                      {['URL structure', 'Domain reputation', 'SSL/TLS signals', 'Suspicious keywords', 'IP and domain information', 'ML risk score'].map((item) => (
                        <div key={item} className="check-row"><Check size={15} /> <span>{item}</span></div>
                      ))}
                    </div>
                  </div>
                </section>

                <section id="report-url" className="card report-panel p-5 md:p-6">
                  <div className="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
                    <div className="max-w-md">
                      <div className="feature-icon"><FileText size={18} /></div>
                      <p className="section-kicker mt-4">Community signal</p>
                      <h2 className="mt-1 text-xl font-semibold text-white">Report a suspicious URL</h2>
                      <p className="mt-2 text-sm leading-6 text-slate-400">Send a link for review and help strengthen the threat intelligence layer.</p>
                    </div>
                    <div className="grid flex-1 gap-3 lg:max-w-3xl lg:grid-cols-[1.4fr_0.8fr_auto]">
                      <input className="input" placeholder="https://example.com" value={reportUrl} onChange={(e) => setReportUrl(e.target.value)} aria-label="URL to report" />
                      <select className="input" value={reportReason} onChange={(e) => setReportReason(e.target.value)} aria-label="Report reason">
                        <option>Phishing</option>
                        <option>Suspicious website</option>
                        <option>Scam</option>
                        <option>Malware</option>
                        <option>Other</option>
                      </select>
                      <button className="btn-primary whitespace-nowrap" onClick={handleReport}>Submit Report</button>
                    </div>
                  </div>
                </section>

                <section className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
                  <div className="card p-5">
                    <h3 className="mb-4 flex items-center gap-2 text-lg font-semibold text-white"><BarChart3 size={18} /> Scan activity</h3>
                    <div className="h-60">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={stats.dailyScans.length ? stats.dailyScans : [{ day: 'N/A', scans: 0 }] }>
                          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                          <XAxis dataKey="day" stroke="#94a3b8" />
                          <YAxis stroke="#94a3b8" />
                          <Tooltip />
                          <Bar dataKey="scans" fill="#22d3ee" radius={[6, 6, 0, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  <div className="card p-5">
                    <h3 className="mb-4 flex items-center gap-2 text-lg font-semibold text-white"><ChartNoAxesCombined size={18} /> Threat distribution</h3>
                    <div className="h-60">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie data={threatDistribution} dataKey="value" nameKey="name" innerRadius={40} outerRadius={75} paddingAngle={4}>
                            {threatDistribution.map((entry, index) => <Cell key={entry.name} fill={pieColors[index % pieColors.length]} />)}
                          </Pie>
                          <Tooltip />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                </section>

                {/* Live Analysis Feed */}
                <section className="card p-5">
                  <div className="mb-4 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                    <h3 className="flex items-center gap-2 text-lg font-semibold text-white"><Activity size={18} /> Live Analysis Feed</h3>
                    <div className="flex items-center gap-3">
                      <label className="text-sm text-slate-400">Filter:</label>
                      <select
                        className="rounded-xl border border-slate-700 bg-slate-950/80 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-400"
                        value={filterStatus}
                        onChange={(e) => setFilterStatus(e.target.value)}
                      >
                        <option value="All Status">All Status</option>
                        <option value="Phishing">Phishing</option>
                        <option value="Suspicious">Suspicious</option>
                        <option value="Safe">Safe</option>
                      </select>
                    </div>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm">
                      <thead>
                        <tr className="border-b border-slate-700 text-slate-400">
                          <th className="pb-3 font-medium">Timestamp</th>
                          <th className="pb-3 font-medium">Target URL</th>
                          <th className="pb-3 font-medium">Risk Score (%)</th>
                          <th className="pb-3 font-medium">Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800">
                        {filteredHistory.length === 0 ? (
                          <tr>
                            <td colSpan={4} className="py-8 text-center text-sm text-slate-400">No scans yet. Run a URL scan to begin.</td>
                          </tr>
                        ) : (
                          filteredHistory.map((item) => (
                            <tr key={item.id} className="transition hover:bg-slate-900/50">
                              <td className="py-3 text-slate-300">{new Date(item.created_at).toLocaleString()}</td>
                              <td className="py-3 text-slate-200">
                                <span className="truncate block max-w-xs">{item.url}</span>
                              </td>
                              <td className="py-3">
                                <div className="flex items-center gap-2">
                                  <div className="h-2 w-24 rounded-full bg-slate-800">
                                    <div
                                      className={`h-2 rounded-full ${getRiskColor(item.risk)}`}
                                      style={{ width: `${Math.min(Number(item.risk || 0) * 100, 100)}%` }}
                                    />
                                  </div>
                                  <span className="text-slate-300">{Number(item.risk * 100).toFixed(1)}%</span>
                                </div>
                              </td>
                              <td className="py-3">
                                <span className={`badge ${getStatusBadge(item.prediction)}`}>
                                  {getStatusLabel(item.prediction)}
                                </span>
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </section>
              </div>
            ) : (
              <div className="mx-auto max-w-xl">
                <div className="card p-6 md:p-8">
                  <div className="mb-6 flex items-center justify-center gap-3 text-center">
                    <div className="rounded-xl bg-cyan-500/10 p-2 text-cyan-300"><Shield /></div>
                    <div>
                      <h1 className="text-2xl font-bold text-white">PhishSense</h1>
                      <p className="text-sm text-slate-400">Secure URL Threat Detection</p>
                    </div>
                  </div>

                  <div className="flex rounded-xl border border-slate-700 bg-slate-950/80 p-1">
                    <button
                      className={`flex-1 rounded-lg py-2.5 text-sm font-medium transition ${authMode === 'login' ? 'bg-cyan-500 text-slate-950' : 'text-slate-300 hover:text-white'}`}
                      onClick={() => setAuthMode('login')}
                    >
                      Login
                    </button>
                    <button
                      className={`flex-1 rounded-lg py-2.5 text-sm font-medium transition ${authMode === 'register' ? 'bg-cyan-500 text-slate-950' : 'text-slate-300 hover:text-white'}`}
                      onClick={() => setAuthMode('register')}
                    >
                      Register
                    </button>
                  </div>

                  <form onSubmit={handleAuth} className="mt-6 space-y-4">
                    {authMode === 'register' && (
                      <input
                        className="input"
                        value={authForm.name}
                        onChange={(e) => setAuthForm({ ...authForm, name: e.target.value })}
                        placeholder="Full name"
                        required
                      />
                    )}
                    <input
                      className="input"
                      type="email"
                      value={authForm.email}
                      onChange={(e) => setAuthForm({ ...authForm, email: e.target.value })}
                      placeholder="Email address"
                      required
                    />
                    <div className="relative">
                      <input
                        className="input pr-12"
                        type={showPassword ? 'text' : 'password'}
                        value={authForm.password}
                        onChange={(e) => {
                          const password = e.target.value;
                          setAuthForm((current) => ({ ...current, password }));
                          if (authMode === 'register' && password && password === authForm.confirmPassword) {
                            setPasswordError('');
                          }
                        }}
                        placeholder="Password"
                        required
                        minLength={6}
                      />
                      <button
                        type="button"
                        className="absolute inset-y-0 right-0 flex items-center px-4 text-slate-400 transition hover:text-cyan-300"
                        onClick={() => setShowPassword((visible) => !visible)}
                        aria-label={showPassword ? 'Hide password' : 'Show password'}
                      >
                        {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                      </button>
                    </div>
                    {authMode === 'register' && (
                      <div className="relative">
                        <input
                          className="input pr-12"
                          type={showConfirmPassword ? 'text' : 'password'}
                          value={authForm.confirmPassword}
                          onChange={(e) => {
                            const confirmPassword = e.target.value;
                            setAuthForm((current) => ({ ...current, confirmPassword }));
                            if (confirmPassword && confirmPassword === authForm.password) {
                              setPasswordError('');
                            }
                          }}
                          placeholder="Confirm Password"
                          required
                        />
                        <button
                          type="button"
                          className="absolute inset-y-0 right-0 flex items-center px-4 text-slate-400 transition hover:text-cyan-300"
                          onClick={() => setShowConfirmPassword((visible) => !visible)}
                          aria-label={showConfirmPassword ? 'Hide confirm password' : 'Show confirm password'}
                        >
                          {showConfirmPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                        </button>
                      </div>
                    )}
                    {authMode === 'register' && passwordError && (
                      <p className="text-sm text-rose-300" role="alert">{passwordError}</p>
                    )}
                    {authMode === 'login' && (
                      <label className="flex items-center gap-2 text-sm text-slate-300">
                        <input
                          type="checkbox"
                          className="h-4 w-4 rounded border-slate-600 bg-slate-900 text-cyan-500 focus:ring-cyan-500/40"
                          checked={rememberMe}
                          onChange={(e) => setRememberMe(e.target.checked)}
                        />
                        Remember me
                      </label>
                    )}
                    <button className="btn-primary w-full" type="submit">
                      {authMode === 'login' ? 'Sign in' : 'Create account'}
                    </button>
                  </form>

                </div>
              </div>
            )
          } />
        </Routes>
      </main>
    </div>
  );
}

export default App;
