import { useEffect, useMemo, useState } from 'react';
import { Link, Route, Routes, Navigate } from 'react-router-dom';
import axios from 'axios';
import { Activity, AlertTriangle, BarChart3, Bot, Check, CheckCircle2, FileText, Globe2, KeyRound, Lock, Network, ScanLine, SearchCheck, Shield, ShieldAlert, ShieldCheck, Settings, TriangleAlert, UserCircle2, ChartNoAxesCombined, X } from 'lucide-react';
import { AreaChart, Area, BarChart, Bar, CartesianGrid, PieChart, Pie, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';

const API_BASE = 'http://localhost:8000';
const DEFAULT_ADMIN = { email: 'admin@college.edu', password: 'admin123' };

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

function App() {
  const [token, setToken] = useState(() => localStorage.getItem('token') || sessionStorage.getItem('token') || '');
  const [user, setUser] = useState(() => JSON.parse(localStorage.getItem('user') || sessionStorage.getItem('user') || 'null'));
  const [scanResult, setScanResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [authMode, setAuthMode] = useState('login');
  const [authForm, setAuthForm] = useState({ name: '', email: '', password: '' });
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
  const isAdmin = user?.role === 'admin';

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
      const res = await axios.get(`${API_BASE}/api/admin/summary`, buildAuthHeader(token));
      setStats(res.data);
    } catch (error) {
      console.error('Stats load failed', error);
    }
  };

  const handleAuth = async (e) => {
    e.preventDefault();

    const payload = authMode === 'register'
      ? authForm
      : { email: authForm.email, password: authForm.password };

    try {
      const endpoint = authMode === 'register' ? '/api/auth/register' : '/api/auth/login';
      const res = await axios.post(`${API_BASE}${endpoint}`, payload);
      setToken(res.data.token);
      setUser(res.data.user);
      setRememberMe(authMode === 'register' ? true : rememberMe);
      setAuthForm({ name: '', email: '', password: '' });
    } catch (error) {
      alert(error.response?.data?.detail || 'Authentication failed');
    }
  };

  const handleDemoAdminLogin = async () => {
    const payload = { email: DEFAULT_ADMIN.email, password: DEFAULT_ADMIN.password };
    try {
      const res = await axios.post(`${API_BASE}/api/auth/login`, payload);
      setToken(res.data.token);
      setUser(res.data.user);
      setAuthForm({ name: '', email: '', password: '' });
    } catch (error) {
      alert('Demo admin login failed.');
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

  const adminSummary = useMemo(() => [
    { name: 'Legitimate', value: stats.counts.legitimate },
    { name: 'Phishing', value: stats.counts.phishing },
    { name: 'Suspicious', value: stats.counts.suspicious },
  ], [stats]);

  const scanSummary = useMemo(() => [
    { name: 'Scans', value: history.length },
    { name: 'Reports', value: stats.reports.total },
    { name: 'Verified', value: stats.reports.verified },
  ], [history.length, stats.reports]);

  const reportTrend = useMemo(() => {
    const base = stats.dailyScans.length ? stats.dailyScans : [{ day: 'today', scans: 0 }];
    return base.map((entry) => ({
      day: entry.day,
      scans: entry.scans,
      phishing: stats.counts.phishing || 0,
      reports: stats.reports.total || 0,
    }));
  }, [stats]);

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
            {isAuthenticated && <Link to="/admin" className="hover:text-white">Admin</Link>}
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
            ) : (
              <button className="btn-primary" onClick={handleDemoAdminLogin}>Demo Admin</button>
            )}
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
                          <Pie data={adminSummary} dataKey="value" nameKey="name" innerRadius={40} outerRadius={75} paddingAngle={4}>
                            {adminSummary.map((entry, index) => <Cell key={entry.name} fill={pieColors[index % pieColors.length]} />)}
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
                    <input
                      className="input"
                      type="password"
                      value={authForm.password}
                      onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })}
                      placeholder="Password"
                      required
                      minLength={6}
                    />
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

                  <p className="mt-5 text-center text-xs text-slate-400">
                    Demo admin: admin@college.edu / admin123
                  </p>
                </div>
              </div>
            )
          } />

          <Route path="/admin" element={
            !isAuthenticated ? <Navigate to="/" replace /> : isAdmin ? (
              <AdminDashboard stats={stats} fetchStats={fetchStats} token={token} />
            ) : (
              <ProtectedAdminMessage handleDemoAdminLogin={handleDemoAdminLogin} />
            )
          } />
        </Routes>
      </main>
    </div>
  );
}

function ProtectedAdminMessage({ handleDemoAdminLogin }) {
  return (
    <div className="card mx-auto max-w-xl p-8 text-center">
      <ShieldCheck className="mx-auto mb-4 text-cyan-300" />
      <h2 className="text-2xl font-bold text-white">Admin access required</h2>
      <p className="mt-3 text-sm text-slate-300">Only verified administrators can view and approve suspicious URL reports.</p>
      <button className="btn-primary mt-5" onClick={handleDemoAdminLogin}>Use demo admin account</button>
    </div>
  );
}

function AdminDashboard({ stats, token, fetchStats }) {
  const [reports, setReports] = useState([]);
  const [metrics, setMetrics] = useState({ accuracy: 0, precision: 0, recall: 0, f1: 0, confusion_matrix: [[0,0],[0,0]] });

  const loadReports = async () => {
    try {
      const res = await axios.get(`${API_BASE}/api/admin/reports`, buildAuthHeader(token));
      setReports(res.data.reports || []);
    } catch (error) {
      console.error(error);
    }
  };

  const loadMetrics = async () => {
    try {
      const res = await axios.get(`${API_BASE}/api/admin/metrics`, buildAuthHeader(token));
      setMetrics(res.data);
    } catch (error) {
      console.error(error);
    }
  };

  useEffect(() => {
    loadReports();
    loadMetrics();
  }, [token]);

  const decision = async (reportId, status) => {
    try {
      await axios.post(`${API_BASE}/api/admin/reports/${reportId}/decision`, { status }, buildAuthHeader(token));
      await loadReports();
      await loadMetrics();
      await fetchStats();
    } catch (error) {
      alert(error.response?.data?.detail || 'Could not update report');
    }
  };

  const confusionMatrix = metrics.confusion_matrix || [[0, 0], [0, 0]];

  return (
    <div className="space-y-8">
      <section className="grid gap-6 md:grid-cols-4">
        <div className="card p-5"><p className="text-sm text-slate-400">Accuracy</p><p className="mt-3 text-3xl font-bold text-white">{Number(metrics.accuracy * 100 || 0).toFixed(2)}%</p></div>
        <div className="card p-5"><p className="text-sm text-slate-400">Precision</p><p className="mt-3 text-3xl font-bold text-white">{Number(metrics.precision * 100 || 0).toFixed(2)}%</p></div>
        <div className="card p-5"><p className="text-sm text-slate-400">Recall</p><p className="mt-3 text-3xl font-bold text-white">{Number(metrics.recall * 100 || 0).toFixed(2)}%</p></div>
        <div className="card p-5"><p className="text-sm text-slate-400">F1-score</p><p className="mt-3 text-3xl font-bold text-white">{Number(metrics.f1 * 100 || 0).toFixed(2)}%</p></div>
      </section>

      <section className="grid gap-6 lg:grid-cols-[1fr_0.8fr]">
        <div className="card p-5">
          <div className="mb-4 flex items-center justify-between">
            <h3 className="text-lg font-semibold text-white">Verified reports</h3>
            <span className="badge bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">{stats.reports.verified}</span>
          </div>
          <div className="space-y-3">
            {reports.length === 0 ? <p className="text-sm text-slate-400">No reports awaiting review.</p> : reports.map((report) => (
              <div key={report.id} className="rounded-xl border border-slate-700 bg-slate-900/70 p-4">
                <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                  <div>
                    <p className="font-medium text-white">{report.url}</p>
                    <p className="text-xs text-slate-400">Status: {report.status} | {new Date(report.created_at).toLocaleString()}</p>
                  </div>
                  <div className="flex gap-2">
                    <button className="btn-primary" onClick={() => decision(report.id, 'verified')}>Verify</button>
                    <button className="btn-secondary" onClick={() => decision(report.id, 'rejected')}>Reject</button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="card p-5">
          <h3 className="mb-4 flex items-center gap-2 text-lg font-semibold text-white"><CheckCircle2 size={18} /> Confusion matrix</h3>
          <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
            <div className="grid grid-cols-2 gap-2 text-center text-sm">
              <div className="rounded-lg bg-slate-800 p-4 text-emerald-300">{confusionMatrix[0][0]}</div>
              <div className="rounded-lg bg-slate-800 p-4 text-rose-300">{confusionMatrix[0][1]}</div>
              <div className="rounded-lg bg-slate-800 p-4 text-amber-300">{confusionMatrix[1][0]}</div>
              <div className="rounded-lg bg-slate-800 p-4 text-cyan-300">{confusionMatrix[1][1]}</div>
            </div>
            <p className="mt-4 text-xs text-slate-400">Matrix layout: [Actual Legitimate, Actual Phishing] x [Predicted Legitimate, Predicted Phishing]</p>
          </div>
        </div>
      </section>

      <section className="card p-5">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-white">Retraining</h3>
          <button className="btn-primary" onClick={async () => {
            try {
              const res = await axios.post(`${API_BASE}/api/admin/retrain`, {}, buildAuthHeader(token));
              alert(`Retraining complete: ${res.data.message}`);
              await loadMetrics();
              await fetchStats();
            } catch (error) {
              alert(error.response?.data?.detail || 'Retraining failed');
            }
          }}>Retrain model</button>
        </div>
        <p className="text-sm text-slate-300">Only verified reports are merged into the training set; unverified reports are never auto-trained.</p>
      </section>
    </div>
  );
}

export default App;
