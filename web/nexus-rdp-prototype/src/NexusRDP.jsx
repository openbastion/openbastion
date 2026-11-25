import React, { useState, useEffect, useRef } from 'react';
import {
  Monitor,
  Server,
  Star,
  Folder,
  KeyRound,
  Shield,
  Search,
  Plus,
  Play,
  Settings,
  Power,
  Copy,
  Wifi,
  WifiOff,
  Pin,
  PinOff,
  ChevronDown,
  Activity,
  Upload,
  Camera,
  Maximize2,
  Minimize2,
  X,
  Lock,
  Unlock,
  Check,
  Terminal,
  FolderDown,
  HardDrive,
  Mic,
  Usb,
  Clipboard,
  Sparkles,
  RefreshCw,
  LayoutGrid,
  List,
  PanelLeftClose,
  PanelLeftOpen,
  Command,
  Cpu,
  Globe,
  AlertTriangle,
  FileText,
  ArrowUpRight
} from 'lucide-react';

const INITIAL_CONNECTIONS = [
  {
    id: 'conn-1',
    name: 'Prod-DB-Primary',
    host: '10.240.12.8',
    port: 3389,
    user: 'CORP\\svc_dbadmin',
    os: 'Windows Server 2025',
    osType: 'windows',
    folder: 'Production Servers',
    pinned: true,
    status: 'online',
    latency: 14,
    accent: '#3B82F6',
    gateway: 'gw-eu-west.nexus.internal',
    scaling: 'fit',
    monitors: [1, 2],
    profile: 'lan',
    redirection: { clipboard: true, audio: false, drives: true, smartcard: true, usb: false },
    wallpaper: 'from-blue-950 via-slate-900 to-indigo-950'
  },
  {
    id: 'conn-2',
    name: 'Workstation-Dev01',
    host: '192.168.1.42',
    port: 3389,
    user: 'alex.mercer',
    os: 'Windows 11 Pro 24H2',
    osType: 'windows',
    folder: 'Home Lab',
    pinned: true,
    status: 'online',
    latency: 6,
    accent: '#10B981',
    gateway: 'Direct (LAN)',
    scaling: 'fit',
    monitors: [1, 2, 3],
    profile: 'lan',
    redirection: { clipboard: true, audio: true, drives: true, smartcard: false, usb: true },
    wallpaper: 'from-emerald-950 via-slate-900 to-teal-950'
  },
  {
    id: 'conn-3',
    name: 'M4-Build-Runner',
    host: '192.168.1.88',
    port: 5900,
    user: 'ci-runner',
    os: 'macOS Sequoia 15.2',
    osType: 'macos',
    folder: 'Home Lab',
    pinned: false,
    status: 'sleeping',
    latency: null,
    accent: '#F59E0B',
    gateway: 'Direct (LAN)',
    scaling: 'retina',
    monitors: [1],
    profile: 'balanced',
    redirection: { clipboard: true, audio: true, drives: false, smartcard: false, usb: false },
    wallpaper: 'from-amber-950 via-slate-900 to-orange-950'
  },
  {
    id: 'conn-4',
    name: 'Ubuntu-K8s-Jumpbox',
    host: '172.16.80.14',
    port: 3389,
    user: 'ubuntu',
    os: 'Ubuntu 24.04 LTS (xrdp)',
    osType: 'linux',
    folder: 'Cloud VMs',
    pinned: true,
    status: 'online',
    latency: 42,
    accent: '#8B5CF6',
    gateway: 'Tailscale Mesh',
    scaling: 'fit',
    monitors: [1],
    profile: 'balanced',
    redirection: { clipboard: true, audio: false, drives: true, smartcard: false, usb: false },
    wallpaper: 'from-purple-950 via-slate-900 to-fuchsia-950'
  },
  {
    id: 'conn-5',
    name: 'Azure-GPU-Render04',
    host: '20.114.88.201',
    port: 3389,
    user: 'render_ops',
    os: 'Windows 11 Enterprise',
    osType: 'windows',
    folder: 'Cloud VMs',
    pinned: false,
    status: 'online',
    latency: 68,
    accent: '#06B6D4',
    gateway: 'rdg-eastus.azure.net',
    scaling: '1to1',
    monitors: [1, 2],
    profile: 'balanced',
    redirection: { clipboard: true, audio: true, drives: true, smartcard: true, usb: false },
    wallpaper: 'from-cyan-950 via-slate-900 to-blue-950'
  },
  {
    id: 'conn-6',
    name: 'FinOps-Core-02',
    host: '10.240.18.91',
    port: 3389,
    user: 'CORP\\auditor_01',
    os: 'Windows Server 2022',
    osType: 'windows',
    folder: 'Production Servers',
    pinned: false,
    status: 'online',
    latency: 19,
    accent: '#EC4899',
    gateway: 'gw-eu-west.nexus.internal',
    scaling: 'fit',
    monitors: [1],
    profile: 'low',
    redirection: { clipboard: false, audio: false, drives: false, smartcard: true, usb: false },
    wallpaper: 'from-rose-950 via-slate-900 to-slate-950'
  }
];

const CREDENTIALS = [
  { id: 'cred-1', label: 'CORP Domain Admin', username: 'CORP\\svc_dbadmin', method: 'Kerberos / SmartCard', lastUsed: '2 mins ago' },
  { id: 'cred-2', label: 'Local Workstation Key', username: 'alex.mercer', method: 'Windows Hello PIN', lastUsed: '1 hour ago' },
  { id: 'cred-3', label: 'Cloud Linux xrdp', username: 'ubuntu', method: 'Ed25519 + Password', lastUsed: 'Yesterday' },
  { id: 'cred-4', label: 'Azure Render Identity', username: 'render_ops', method: 'Entra ID SSO', lastUsed: '3 days ago' }
];

const PHYSICAL_MONITORS = [
  { id: 1, name: 'Display 1 (Primary)', res: '3840 × 2160 • 144Hz', width: 'w-32', height: 'h-20' },
  { id: 2, name: 'Display 2 (Left)', res: '2560 × 1440 • 120Hz', width: 'w-28', height: 'h-16' },
  { id: 3, name: 'Display 3 (Vertical)', res: '1440 × 2560 • 60Hz', width: 'w-14', height: 'h-24' }
];

export default function NexusRDP() {
  const [connections, setConnections] = useState(INITIAL_CONNECTIONS);
  const [activeNav, setActiveNav] = useState('All Workspaces');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [viewMode, setViewMode] = useState('grid');
  const [searchQuery, setSearchQuery] = useState('');
  const [adHocAddress, setAdHocAddress] = useState('');
  const [tunnels, setTunnels] = useState({ wireguard: true, tailscale: true, rdGateway: false });
  const [wakingIds, setWakingIds] = useState({});

  // Config Drawer State
  const [editingConn, setEditingConn] = useState(null);
  const [drawerTab, setDrawerTab] = useState('general');

  // Active Session State
  const [openSessions, setOpenSessions] = useState([]);
  const [activeSessionId, setActiveSessionId] = useState(null);
  const [hudPinned, setHudPinned] = useState(true);
  const [hudVisible, setHudVisible] = useState(true);
  const [sessionSwitcherOpen, setSessionSwitcherOpen] = useState(false);
  const [telemetryOpen, setTelemetryOpen] = useState(false);
  const [fileDrawerOpen, setFileDrawerOpen] = useState(false);
  const [keyboardCaptured, setKeyboardCaptured] = useState(true);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [reconnecting, setReconnecting] = useState(false);
  const [reconnectAttempt, setReconnectAttempt] = useState(1);
  const [toast, setToast] = useState(null);

  // Simulated Remote Desktop State
  const [remoteFiles, setRemoteFiles] = useState([
    { name: 'deploy-manifest-v4.yaml', size: '18.4 KB', time: 'Today, 09:41' },
    { name: 'db-migration-snapshot.sql', size: '142.8 MB', time: 'Yesterday, 18:12' }
  ]);
  const [terminalLines, setTerminalLines] = useState([
    'Microsoft Windows [Version 10.0.26100.2314]',
    '(c) Microsoft Corporation. All rights reserved.',
    '',
    'PS C:\\Users\\Admin> Get-NetTCPConnection -LocalPort 3389 | Select State, RemoteAddress',
    'State       RemoteAddress',
    '-----       -------------',
    'Established 192.168.1.10',
    'PS C:\\Users\\Admin> _'
  ]);
  const [liveLatency, setLiveLatency] = useState(14);
  const [latencyHistory, setLatencyHistory] = useState([15, 14, 16, 13, 14, 15, 14, 12, 14, 15, 14, 13]);

  const searchInputRef = useRef(null);
  const hudTimeoutRef = useRef(null);

  const showToast = (message, type = 'info') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 3200);
  };

  // Cmd/Ctrl + K Shortcut
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (activeSessionId) {
          setActiveSessionId(null);
        }
        setTimeout(() => searchInputRef.current?.focus(), 50);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [activeSessionId]);

  // Live latency jitter simulation inside active session
  useEffect(() => {
    if (!activeSessionId || reconnecting) return;
    const base = openSessions.find((s) => s.id === activeSessionId)?.latency || 16;
    const interval = setInterval(() => {
      const jitter = Math.floor(Math.random() * 7) - 3;
      const next = Math.max(4, base + jitter);
      setLiveLatency(next);
      setLatencyHistory((prev) => [...prev.slice(1), next]);
    }, 1500);
    return () => clearInterval(interval);
  }, [activeSessionId, openSessions, reconnecting]);

  // HUD Auto-hide when unpinned
  useEffect(() => {
    if (!activeSessionId) return;
    if (hudPinned || sessionSwitcherOpen || telemetryOpen || fileDrawerOpen) {
      setHudVisible(true);
      if (hudTimeoutRef.current) clearTimeout(hudTimeoutRef.current);
      return;
    }
    hudTimeoutRef.current = setTimeout(() => {
      setHudVisible(false);
    }, 3000);
    return () => clearTimeout(hudTimeoutRef.current);
  }, [activeSessionId, hudPinned, sessionSwitcherOpen, telemetryOpen, fileDrawerOpen]);

  const handleWakeOnLan = (conn) => {
    setWakingIds((prev) => ({ ...prev, [conn.id]: true }));
    showToast(`Sent magic WoL packet to ${conn.name} (${conn.host})...`);
    setTimeout(() => {
      setConnections((prev) =>
        prev.map((c) => (c.id === conn.id ? { ...c, status: 'online', latency: 9 } : c))
      );
      setWakingIds((prev) => ({ ...prev, [conn.id]: false }));
      showToast(`${conn.name} is now online (9ms)`, 'success');
    }, 1800);
  };

  const handleConnect = (conn) => {
    if (conn.status === 'sleeping') {
      handleWakeOnLan(conn);
      return;
    }
    if (!openSessions.some((s) => s.id === conn.id)) {
      setOpenSessions((prev) => [...prev, conn]);
    }
    setActiveSessionId(conn.id);
    setLiveLatency(conn.latency || 15);
    setReconnecting(false);
    setSessionSwitcherOpen(false);
    setTelemetryOpen(false);
    setFileDrawerOpen(false);
  };

  const handleAdHocConnect = (e) => {
    e.preventDefault();
    if (!adHocAddress.trim()) return;
    const cleanHost = adHocAddress.replace(/^rdp:\/\//i, '').trim();
    const adHocConn = {
      id: `adhoc-${Date.now()}`,
      name: cleanHost.split(':')[0],
      host: cleanHost.includes(':') ? cleanHost.split(':')[0] : cleanHost,
      port: cleanHost.includes(':') ? Number(cleanHost.split(':')[1]) || 3389 : 3389,
      user: 'Administrator',
      os: 'Remote Windows Host',
      osType: 'windows',
      folder: 'Quick Connect',
      pinned: false,
      status: 'online',
      latency: 22,
      accent: '#3B82F6',
      gateway: 'Direct TLS',
      scaling: 'fit',
      monitors: [1],
      profile: 'balanced',
      redirection: { clipboard: true, audio: true, drives: true, smartcard: false, usb: false },
      wallpaper: 'from-slate-900 via-blue-950 to-slate-950'
    };
    setAdHocAddress('');
    handleConnect(adHocConn);
  };

  const handleDisconnect = (id) => {
    const remaining = openSessions.filter((s) => s.id !== id);
    setOpenSessions(remaining);
    if (activeSessionId === id) {
      setActiveSessionId(remaining.length > 0 ? remaining[remaining.length - 1].id : null);
    }
    showToast('Session disconnected cleanly (remote state preserved)');
  };

  const handleSimulateDrop = () => {
    setTelemetryOpen(false);
    setReconnecting(true);
    setReconnectAttempt(1);
    const t1 = setTimeout(() => setReconnectAttempt(2), 1300);
    const t2 = setTimeout(() => setReconnectAttempt(3), 2600);
    const t3 = setTimeout(() => {
      setReconnecting(false);
      showToast('UDP stream restored — 0 frames lost', 'success');
    }, 3900);
    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
    };
  };

  const handleSendCtrlAltDel = () => {
    setTerminalLines((prev) => [
      ...prev.slice(0, -1),
      'PS C:\\Users\\Admin> [SAS] Secure Attention Sequence (Ctrl+Alt+Del) injected into Winlogon',
      'PS C:\\Users\\Admin> _'
    ]);
    showToast('Sent Ctrl+Alt+Del Secure Attention Sequence');
  };

  const handleSimulateFileUpload = () => {
    const newFile = {
      name: `release-patch-${Math.floor(100 + Math.random() * 900)}.zip`,
      size: '24.6 MB',
      time: 'Just now'
    };
    setRemoteFiles((prev) => [newFile, ...prev]);
    setTerminalLines((prev) => [
      ...prev.slice(0, -1),
      `PS C:\\Users\\Admin> [RDPDR] Synced "${newFile.name}" -> C:\\Users\\Admin\\Downloads\\`,
      'PS C:\\Users\\Admin> _'
    ]);
    showToast(`Uploaded ${newFile.name} to remote Downloads`, 'success');
  };

  const openNewConnectionDrawer = () => {
    setDrawerTab('general');
    setEditingConn({
      id: `conn-${Date.now()}`,
      name: 'New-Remote-Host',
      host: '10.0.0.50',
      port: 3389,
      user: 'Administrator',
      os: 'Windows 11 Pro',
      osType: 'windows',
      folder: 'Home Lab',
      pinned: false,
      status: 'online',
      latency: 15,
      accent: '#3B82F6',
      gateway: 'Direct (LAN)',
      scaling: 'fit',
      monitors: [1],
      profile: 'lan',
      redirection: { clipboard: true, audio: true, drives: true, smartcard: false, usb: false },
      wallpaper: 'from-blue-950 via-slate-900 to-slate-950',
      isNew: true
    });
  };

  const saveConnectionConfig = () => {
    if (!editingConn) return;
    if (editingConn.isNew) {
      const { isNew, ...clean } = editingConn;
      setConnections((prev) => [clean, ...prev]);
      showToast(`Created workspace "${clean.name}"`, 'success');
    } else {
      setConnections((prev) => prev.map((c) => (c.id === editingConn.id ? editingConn : c)));
      setOpenSessions((prev) => prev.map((s) => (s.id === editingConn.id ? editingConn : s)));
      showToast(`Saved configuration for ${editingConn.name}`, 'success');
    }
    setEditingConn(null);
  };

  const toggleMonitorSelection = (monId) => {
    if (!editingConn) return;
    const exists = editingConn.monitors.includes(monId);
    if (exists && editingConn.monitors.length === 1) return;
    const nextMonitors = exists
      ? editingConn.monitors.filter((m) => m !== monId)
      : [...editingConn.monitors, monId].sort();
    setEditingConn({ ...editingConn, monitors: nextMonitors });
  };

  const filteredConnections = connections.filter((conn) => {
    const matchesSearch =
      conn.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      conn.host.toLowerCase().includes(searchQuery.toLowerCase()) ||
      conn.os.toLowerCase().includes(searchQuery.toLowerCase()) ||
      conn.folder.toLowerCase().includes(searchQuery.toLowerCase());

    if (!matchesSearch) return false;
    if (activeNav === 'All Workspaces') return true;
    if (activeNav === 'Pinned') return conn.pinned;
    return conn.folder === activeNav;
  });

  const activeSession = openSessions.find((s) => s.id === activeSessionId);

  const getLatencyColor = (ms) => {
    if (ms === null) return 'text-slate-500';
    if (ms < 30) return 'text-emerald-400';
    if (ms <= 90) return 'text-amber-400';
    return 'text-rose-400';
  };

  const getLatencyDot = (ms) => {
    if (ms === null) return 'bg-slate-500';
    if (ms < 30) return 'bg-emerald-400';
    if (ms <= 90) return 'bg-amber-400';
    return 'bg-rose-400';
  };

  // ============================================================================
  // VIEW 2: ACTIVE SESSION CANVAS
  // ============================================================================
  if (activeSession) {
    return (
      <div
        className="relative h-screen w-screen overflow-hidden bg-[#090B0E] select-none flex flex-col"
        onMouseMove={(e) => {
          if (e.clientY < 48) setHudVisible(true);
        }}
      >
        <div
          className="absolute top-0 left-0 right-0 h-3 z-40"
          onMouseEnter={() => setHudVisible(true)}
        />

        {/* FLOATING EDGE HUD ("The Floating Pill") */}
        <div
          className={`fixed top-3 left-1/2 -translate-x-1/2 z-50 transition-all duration-300 ${
            hudVisible ? 'opacity-100 translate-y-0' : 'opacity-0 -translate-y-12 pointer-events-none'
          }`}
        >
          <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-full bg-[#14171D]/90 backdrop-blur-xl border border-[#2A2F3A] shadow-2xl shadow-black/70 text-xs">
            <button
              onClick={() => setHudPinned(!hudPinned)}
              title={hudPinned ? 'Unpin HUD (Auto-hide)' : 'Pin HUD'}
              className={`p-1.5 rounded-full transition-colors ${
                hudPinned ? 'bg-blue-500/20 text-blue-400' : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
            >
              {hudPinned ? <Pin className="w-3.5 h-3.5" /> : <PinOff className="w-3.5 h-3.5" />}
            </button>

            <div className="h-4 w-[1px] bg-[#2A2F3A]" />

            {/* Session Switcher Dropdown */}
            <div className="relative">
              <button
                onClick={() => {
                  setSessionSwitcherOpen(!sessionSwitcherOpen);
                  setTelemetryOpen(false);
                  setFileDrawerOpen(false);
                }}
                className="flex items-center gap-2 px-2.5 py-1 rounded-full hover:bg-white/5 text-slate-200 font-medium transition-colors"
              >
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span>{activeSession.name}</span>
                <span className="text-[10px] font-mono text-slate-400 hidden sm:inline">
                  ({activeSession.monitors.length} {activeSession.monitors.length > 1 ? 'Displays' : 'Display'})
                </span>
                <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
              </button>

              {sessionSwitcherOpen && (
                <div className="absolute top-10 left-0 w-72 rounded-xl bg-[#181B20] border border-[#2A2F3A] shadow-2xl p-2 z-50">
                  <div className="px-2 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                    Active Sessions ({openSessions.length})
                  </div>
                  <div className="space-y-1 mt-1">
                    {openSessions.map((sess) => (
                      <div
                        key={sess.id}
                        onClick={() => {
                          setActiveSessionId(sess.id);
                          setSessionSwitcherOpen(false);
                        }}
                        className={`flex items-center justify-between px-2.5 py-2 rounded-lg cursor-pointer transition-colors ${
                          sess.id === activeSession.id
                            ? 'bg-blue-500/15 border border-blue-500/30 text-white'
                            : 'hover:bg-white/5 text-slate-300'
                        }`}
                      >
                        <div>
                          <div className="font-medium text-xs flex items-center gap-2">
                            <span className={`w-1.5 h-1.5 rounded-full ${getLatencyDot(sess.latency)}`} />
                            {sess.name}
                          </div>
                          <div className="text-[11px] font-mono text-slate-400">{sess.host}</div>
                        </div>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleDisconnect(sess.id);
                          }}
                          className="p-1 text-slate-400 hover:text-rose-400 rounded"
                          title="Disconnect session"
                        >
                          <X className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                  <div className="border-t border-[#2A2F3A] mt-2 pt-2">
                    <button
                      onClick={() => {
                        setSessionSwitcherOpen(false);
                        setActiveSessionId(null);
                      }}
                      className="w-full flex items-center justify-center gap-1.5 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-slate-200 text-xs font-medium transition-colors"
                    >
                      <LayoutGrid className="w-3.5 h-3.5 text-blue-400" />
                      Return to Connection Hub
                    </button>
                  </div>
                </div>
              )}
            </div>

            <div className="h-4 w-[1px] bg-[#2A2F3A]" />

            {/* Telemetry Pill */}
            <div className="relative">
              <button
                onClick={() => {
                  setTelemetryOpen(!telemetryOpen);
                  setSessionSwitcherOpen(false);
                  setFileDrawerOpen(false);
                }}
                className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-[#1E222B] hover:bg-[#252A35] border border-[#2A2F3A] font-mono text-[11px] transition-colors"
              >
                <Activity className={`w-3.5 h-3.5 ${getLatencyColor(liveLatency)}`} />
                <span className={getLatencyColor(liveLatency)}>{liveLatency}ms</span>
                <span className="text-slate-500">•</span>
                <span className="text-slate-300">60 FPS</span>
                <span className="text-slate-500 hidden md:inline">•</span>
                <span className="text-blue-400 hidden md:inline">UDP</span>
              </button>

              {telemetryOpen && (
                <div className="absolute top-10 left-1/2 -translate-x-1/2 w-80 rounded-xl bg-[#181B20] border border-[#2A2F3A] shadow-2xl p-4 z-50">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xs font-semibold text-white">Stream Telemetry</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                      H.264 / AVC 444
                    </span>
                  </div>

                  <div className="bg-[#0F1115] rounded-lg p-3 border border-[#2A2F3A] mb-3">
                    <div className="flex justify-between text-[10px] font-mono text-slate-400 mb-2">
                      <span>RTT Latency History</span>
                      <span className="text-emerald-400">Jitter: 1.4ms</span>
                    </div>
                    <div className="flex items-end gap-1 h-10">
                      {latencyHistory.map((val, i) => (
                        <div
                          key={i}
                          style={{ height: `${Math.min(100, Math.max(20, val * 2))}%` }}
                          className={`flex-1 rounded-sm transition-all ${
                            val < 30 ? 'bg-emerald-500/80' : 'bg-amber-500/80'
                          }`}
                        />
                      ))}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-[11px] font-mono mb-3">
                    <div className="bg-[#0F1115] p-2 rounded border border-[#2A2F3A]">
                      <div className="text-slate-500 text-[10px]">Downstream</div>
                      <div className="text-slate-200">14.2 Mbps</div>
                    </div>
                    <div className="bg-[#0F1115] p-2 rounded border border-[#2A2F3A]">
                      <div className="text-slate-500 text-[10px]">Packet Loss</div>
                      <div className="text-emerald-400">0.00%</div>
                    </div>
                  </div>

                  <button
                    onClick={handleSimulateDrop}
                    className="w-full flex items-center justify-center gap-2 py-2 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/30 text-amber-300 text-xs font-medium transition-colors"
                  >
                    <AlertTriangle className="w-3.5 h-3.5" />
                    Simulate Network Drop (Test Smart Reconnect)
                  </button>
                </div>
              )}
            </div>

            <div className="h-4 w-[1px] bg-[#2A2F3A]" />

            {/* Quick Utilities */}
            <button
              onClick={handleSendCtrlAltDel}
              className="px-2 py-1 rounded-full hover:bg-white/10 text-slate-300 hover:text-white font-mono text-[11px] transition-colors"
              title="Send Ctrl+Alt+Del"
            >
              Ctrl+Alt+Del
            </button>

            <div className="relative">
              <button
                onClick={() => {
                  setFileDrawerOpen(!fileDrawerOpen);
                  setSessionSwitcherOpen(false);
                  setTelemetryOpen(false);
                }}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-full hover:bg-white/10 text-slate-300 hover:text-white transition-colors"
                title="Clipboard & File Transfer"
              >
                <Upload className="w-3.5 h-3.5 text-blue-400" />
                <span className="hidden md:inline">Files</span>
              </button>

              {fileDrawerOpen && (
                <div className="absolute top-10 right-0 w-80 rounded-xl bg-[#181B20] border border-[#2A2F3A] shadow-2xl p-4 z-50">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-semibold text-white">RDP Drive Redirection</span>
                    <span className="text-[10px] font-mono text-emerald-400">Bidirectional Sync</span>
                  </div>
                  <p className="text-[11px] text-slate-400 mb-3">
                    Push files directly to <code className="text-slate-200">C:\Users\Admin\Downloads</code>
                  </p>
                  <button
                    onClick={handleSimulateFileUpload}
                    className="w-full py-3 px-3 border border-dashed border-blue-500/40 hover:border-blue-400 bg-blue-500/10 hover:bg-blue-500/15 rounded-lg flex flex-col items-center justify-center gap-1 text-blue-300 transition-colors mb-3"
                  >
                    <Upload className="w-4 h-4" />
                    <span className="text-xs font-medium">Click to Push Sample Build Artifact</span>
                  </button>
                  <div className="space-y-1.5 max-h-36 overflow-y-auto">
                    {remoteFiles.map((file, idx) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between text-[11px] bg-[#0F1115] px-2.5 py-1.5 rounded border border-[#2A2F3A]"
                      >
                        <div className="flex items-center gap-2 truncate">
                          <FileText className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                          <span className="truncate text-slate-200">{file.name}</span>
                        </div>
                        <span className="font-mono text-[10px] text-slate-500 shrink-0 ml-2">{file.size}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <button
              onClick={() => showToast('Captured remote viewport (3840×2160) to local clipboard', 'success')}
              className="p-1.5 rounded-full hover:bg-white/10 text-slate-300 hover:text-white transition-colors"
              title="Capture Viewport Screenshot"
            >
              <Camera className="w-3.5 h-3.5" />
            </button>

            <button
              onClick={() => {
                setKeyboardCaptured(!keyboardCaptured);
                showToast(
                  !keyboardCaptured
                    ? 'System shortcuts (Win/Alt+Tab) captured by Remote OS'
                    : 'System shortcuts routed to Local OS'
                );
              }}
              className={`flex items-center gap-1 px-2 py-1 rounded-full text-[10px] font-mono transition-colors ${
                keyboardCaptured
                  ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                  : 'bg-white/5 text-slate-400'
              }`}
              title="Toggle System Shortcut Capture"
            >
              {keyboardCaptured ? <Lock className="w-3 h-3" /> : <Unlock className="w-3 h-3" />}
              <span className="hidden lg:inline">{keyboardCaptured ? 'Keys: Remote' : 'Keys: Local'}</span>
            </button>

            <div className="h-4 w-[1px] bg-[#2A2F3A]" />

            <button
              onClick={() => setIsFullscreen(!isFullscreen)}
              className="p-1.5 rounded-full hover:bg-white/10 text-slate-300 hover:text-white transition-colors"
              title={isFullscreen ? 'Exit Fullscreen' : 'Enter Fullscreen'}
            >
              {isFullscreen ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
            </button>

            <button
              onClick={() => handleDisconnect(activeSession.id)}
              className="p-1.5 rounded-full bg-rose-500/15 hover:bg-rose-500 text-rose-400 hover:text-white transition-colors ml-0.5"
              title="Disconnect Session"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* SIMULATED REMOTE DESKTOP VIEWPORT */}
        <div
          className={`flex-1 relative bg-gradient-to-br ${activeSession.wallpaper} p-6 flex flex-col justify-between transition-all duration-500 ${
            reconnecting ? 'grayscale blur-sm scale-[0.99]' : ''
          }`}
        >
          <div className="grid grid-cols-1 gap-5 w-24 mt-8">
            <div className="flex flex-col items-center gap-1.5 text-center group cursor-pointer">
              <div className="w-11 h-11 rounded-xl bg-white/10 backdrop-blur-md border border-white/15 flex items-center justify-center group-hover:bg-white/20 transition-colors">
                <Monitor className="w-6 h-6 text-blue-300" />
              </div>
              <span className="text-[11px] text-white/90 drop-shadow font-medium">This PC</span>
            </div>
            <div
              onClick={() => setFileDrawerOpen(true)}
              className="flex flex-col items-center gap-1.5 text-center group cursor-pointer"
            >
              <div className="w-11 h-11 rounded-xl bg-white/10 backdrop-blur-md border border-white/15 flex items-center justify-center group-hover:bg-white/20 transition-colors">
                <FolderDown className="w-6 h-6 text-amber-300" />
              </div>
              <span className="text-[11px] text-white/90 drop-shadow font-medium">Downloads</span>
            </div>
          </div>

          <div className="absolute inset-0 pointer-events-none flex items-center justify-center p-6">
            <div className="pointer-events-auto w-full max-w-4xl grid grid-cols-1 lg:grid-cols-5 gap-4">
              <div className="lg:col-span-3 rounded-xl bg-[#0C0E12]/95 backdrop-blur-md border border-white/15 shadow-2xl overflow-hidden flex flex-col">
                <div className="flex items-center justify-between px-3.5 py-2 bg-[#161A22] border-b border-white/10">
                  <div className="flex items-center gap-2 text-xs text-slate-300 font-medium">
                    <Terminal className="w-3.5 h-3.5 text-blue-400" />
                    <span>Administrator: PowerShell 7 — {activeSession.name}</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-slate-600" />
                    <span className="w-2.5 h-2.5 rounded-full bg-slate-600" />
                    <span className="w-2.5 h-2.5 rounded-full bg-rose-500/80" />
                  </div>
                </div>
                <div className="p-4 font-mono text-xs text-slate-300 space-y-1.5 min-h-[210px]">
                  {terminalLines.map((line, i) => (
                    <div key={i} className={line.startsWith('PS ') ? 'text-emerald-400' : 'text-slate-300'}>
                      {line || '\u00A0'}
                    </div>
                  ))}
                </div>
              </div>

              <div className="lg:col-span-2 rounded-xl bg-[#131720]/95 backdrop-blur-md border border-white/15 shadow-2xl overflow-hidden flex flex-col">
                <div className="flex items-center justify-between px-3.5 py-2 bg-[#1A1F2B] border-b border-white/10">
                  <div className="flex items-center gap-2 text-xs text-slate-200 font-medium">
                    <Folder className="w-3.5 h-3.5 text-amber-400" />
                    <span>C:\Users\Admin\Downloads</span>
                  </div>
                </div>
                <div className="p-3 space-y-2 flex-1">
                  {remoteFiles.map((f, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between p-2 rounded-lg bg-white/5 border border-white/5 text-xs"
                    >
                      <div className="truncate pr-2">
                        <div className="text-slate-200 font-medium truncate">{f.name}</div>
                        <div className="text-[10px] text-slate-400">{f.time}</div>
                      </div>
                      <span className="font-mono text-[10px] text-slate-400 shrink-0">{f.size}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="h-10 rounded-xl bg-[#0D1015]/85 backdrop-blur-xl border border-white/10 px-4 flex items-center justify-between text-xs text-slate-300">
            <div className="flex items-center gap-3">
              <div className="w-6 h-6 rounded-md bg-blue-500/20 border border-blue-400/30 flex items-center justify-center text-blue-400 font-bold">
                ⊞
              </div>
              <span className="font-medium text-slate-200">{activeSession.os}</span>
              <span className="hidden sm:inline text-slate-500">|</span>
              <span className="hidden sm:inline font-mono text-[11px] text-slate-400">
                EDID Dynamic Scaling: Active
              </span>
            </div>
            <div className="flex items-center gap-4 font-mono text-[11px] text-slate-400">
              <span>{activeSession.user}</span>
              <span className="text-slate-200">21:14</span>
            </div>
          </div>
        </div>

        {/* SMART RECONNECT OVERLAY */}
        {reconnecting && (
          <div className="absolute inset-0 z-50 bg-black/50 backdrop-blur-md flex items-center justify-center p-4">
            <div className="bg-[#181B20] border border-[#2A2F3A] rounded-2xl p-6 max-w-md w-full shadow-2xl text-center">
              <div className="w-12 h-12 rounded-full bg-amber-500/15 border border-amber-500/30 flex items-center justify-center mx-auto mb-4">
                <RefreshCw className="w-6 h-6 text-amber-400 animate-spin" />
              </div>
              <h3 className="text-base font-semibold text-white mb-1">Connection Interrupted</h3>
              <p className="text-xs text-slate-400 mb-4">
                Packet stream stalled on <span className="font-mono text-slate-200">{activeSession.host}</span>.
                Preserving remote framebuffer state...
              </p>
              <div className="bg-[#0F1115] border border-[#2A2F3A] rounded-lg py-2.5 px-4 font-mono text-xs text-amber-300 mb-4">
                Attempting automatic UDP reconnect (Attempt {reconnectAttempt}/5)...
              </div>
              <button
                onClick={() => handleDisconnect(activeSession.id)}
                className="text-xs text-slate-400 hover:text-white underline"
              >
                Abort and return to Hub
              </button>
            </div>
          </div>
        )}

        {toast && (
          <div className="fixed bottom-16 right-6 z-50 flex items-center gap-2.5 px-4 py-2.5 rounded-xl bg-[#181B20] border border-[#2A2F3A] shadow-2xl text-xs text-slate-100">
            <span
              className={`w-2 h-2 rounded-full ${
                toast.type === 'success' ? 'bg-emerald-400' : 'bg-blue-400'
              }`}
            />
            {toast.message}
          </div>
        )}
      </div>
    );
  }

  // ============================================================================
  // VIEW 1: THE HUB (CONNECTION MANAGER & DASHBOARD)
  // ============================================================================
  return (
    <div className="min-h-screen bg-[#0F1115] text-slate-100 flex overflow-hidden">
      <aside
        className={`${
          sidebarCollapsed ? 'w-16' : 'w-64'
        } bg-[#0B0D10] border-r border-[#2A2F3A]/80 flex flex-col justify-between transition-all duration-200 shrink-0`}
      >
        <div>
          <div className="h-16 px-4 flex items-center justify-between border-b border-[#2A2F3A]/60">
            {!sidebarCollapsed && (
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center shadow-lg shadow-blue-600/25">
                  <Monitor className="w-4 h-4 text-white" />
                </div>
                <div>
                  <div className="font-semibold text-sm tracking-tight text-white">NexusRDP</div>
                  <div className="text-[10px] font-mono text-slate-500">v4.2 OBSIDIAN</div>
                </div>
              </div>
            )}
            <button
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors mx-auto"
              title="Toggle Sidebar"
            >
              {sidebarCollapsed ? <PanelLeftOpen className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
            </button>
          </div>

          <div className="p-3 space-y-1">
            {[
              { label: 'All Workspaces', icon: LayoutGrid, count: connections.length },
              { label: 'Pinned', icon: Star, count: connections.filter((c) => c.pinned).length }
            ].map((item) => {
              const Icon = item.icon;
              const active = activeNav === item.label;
              return (
                <button
                  key={item.label}
                  onClick={() => setActiveNav(item.label)}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                    active
                      ? 'bg-blue-500/15 text-blue-400 border border-blue-500/25'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className="w-4 h-4 shrink-0" />
                    {!sidebarCollapsed && <span>{item.label}</span>}
                  </div>
                  {!sidebarCollapsed && (
                    <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-white/5 text-slate-400">
                      {item.count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          <div className="px-3 pt-3">
            {!sidebarCollapsed && (
              <div className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                Environments
              </div>
            )}
            <div className="space-y-1">
              {['Production Servers', 'Home Lab', 'Cloud VMs'].map((folder) => {
                const active = activeNav === folder;
                return (
                  <button
                    key={folder}
                    onClick={() => setActiveNav(folder)}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                      active
                        ? 'bg-blue-500/15 text-blue-400 border border-blue-500/25'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 truncate">
                      <Folder className="w-4 h-4 shrink-0 text-slate-500" />
                      {!sidebarCollapsed && <span className="truncate">{folder}</span>}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="px-3 pt-4">
            {!sidebarCollapsed && (
              <div className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                Security
              </div>
            )}
            <button
              onClick={() => setActiveNav('Credentials Vault')}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                activeNav === 'Credentials Vault'
                  ? 'bg-blue-500/15 text-blue-400 border border-blue-500/25'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
              }`}
            >
              <KeyRound className="w-4 h-4 shrink-0" />
              {!sidebarCollapsed && <span>Credentials Vault</span>}
            </button>
          </div>
        </div>

        {!sidebarCollapsed && (
          <div className="p-3 m-3 rounded-xl bg-[#14171D] border border-[#2A2F3A]">
            <div className="flex items-center gap-2 text-[11px] font-semibold text-slate-300 mb-2.5">
              <Shield className="w-3.5 h-3.5 text-emerald-400" />
              <span>Mesh & Gateways</span>
            </div>
            <div className="space-y-2 text-xs">
              {[
                { key: 'wireguard', label: 'WireGuard Prod' },
                { key: 'tailscale', label: 'Tailscale Mesh' },
                { key: 'rdGateway', label: 'Azure RD Gateway' }
              ].map((t) => (
                <div key={t.key} className="flex items-center justify-between">
                  <span className="text-slate-400 text-[11px]">{t.label}</span>
                  <button
                    onClick={() => {
                      const next = !tunnels[t.key];
                      setTunnels({ ...tunnels, [t.key]: next });
                      showToast(`${t.label} ${next ? 'connected' : 'disconnected'}`);
                    }}
                    className={`w-8 h-4 rounded-full transition-colors p-0.5 ${
                      tunnels[t.key] ? 'bg-emerald-500' : 'bg-[#2A2F3A]'
                    }`}
                  >
                    <div
                      className={`w-3 h-3 rounded-full bg-white transition-transform ${
                        tunnels[t.key] ? 'translate-x-4' : 'translate-x-0'
                      }`}
                    />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
      </aside>

      <main className="flex-1 flex flex-col h-screen overflow-hidden">
        <header className="h-16 px-6 border-b border-[#2A2F3A]/80 bg-[#0F1115]/90 backdrop-blur-md flex items-center justify-between gap-4 shrink-0">
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              ref={searchInputRef}
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter workspaces by host, IP, OS, or tag..."
              className="w-full bg-[#181B20] border border-[#2A2F3A] focus:border-blue-500 rounded-lg pl-9 pr-14 py-1.5 text-xs text-slate-100 placeholder-slate-500 outline-none transition-colors"
            />
            <span className="absolute right-2.5 top-1/2 -translate-y-1/2 px-1.5 py-0.5 rounded bg-[#0F1115] border border-[#2A2F3A] font-mono text-[10px] text-slate-400">
              ⌘K
            </span>
          </div>

          <form onSubmit={handleAdHocConnect} className="hidden lg:flex items-center gap-2">
            <div className="relative">
              <Globe className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={adHocAddress}
                onChange={(e) => setAdHocAddress(e.target.value)}
                placeholder="rdp://10.0.14.22:3389"
                className="w-56 bg-[#181B20] border border-[#2A2F3A] focus:border-blue-500 rounded-lg pl-8 pr-3 py-1.5 font-mono text-xs text-slate-200 placeholder-slate-500 outline-none"
              />
            </div>
            <button
              type="submit"
              className="px-3 py-1.5 rounded-lg bg-[#181B20] hover:bg-[#22262E] border border-[#2A2F3A] text-xs font-medium text-slate-200 flex items-center gap-1.5 transition-colors"
            >
              <ArrowUpRight className="w-3.5 h-3.5 text-blue-400" />
              Quick Connect
            </button>
          </form>

          <button
            onClick={openNewConnectionDrawer}
            className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium flex items-center gap-1.5 shadow-lg shadow-blue-600/20 transition-colors shrink-0"
          >
            <Plus className="w-4 h-4" />
            <span>New Connection</span>
          </button>
        </header>

        {openSessions.length > 0 && (
          <div className="px-6 py-2.5 bg-blue-500/10 border-b border-blue-500/20 flex items-center justify-between text-xs">
            <div className="flex items-center gap-2 text-blue-300">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>
                {openSessions.length} active background {openSessions.length === 1 ? 'session' : 'sessions'} running
              </span>
            </div>
            <div className="flex items-center gap-2">
              {openSessions.map((s) => (
                <button
                  key={s.id}
                  onClick={() => setActiveSessionId(s.id)}
                  className="px-2.5 py-1 rounded-md bg-blue-600 hover:bg-blue-500 text-white font-medium text-[11px] transition-colors"
                >
                  Resume {s.name}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="flex-1 overflow-y-auto p-6">
          <div className="flex items-center justify-between mb-5">
            <div>
              <h1 className="text-lg font-semibold text-white">{activeNav}</h1>
              <p className="text-xs text-slate-400">
                {activeNav === 'Credentials Vault'
                  ? 'Hardware-backed Kerberos tickets, Windows Hello tokens, and SSH identities'
                  : 'Select a remote host to launch an accelerated UDP/H.264 desktop session'}
              </p>
            </div>

            {activeNav !== 'Credentials Vault' && (
              <div className="flex items-center gap-1 bg-[#181B20] p-1 rounded-lg border border-[#2A2F3A]">
                <button
                  onClick={() => setViewMode('grid')}
                  className={`p-1.5 rounded-md transition-colors ${
                    viewMode === 'grid' ? 'bg-[#2A2F3A] text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <LayoutGrid className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => setViewMode('list')}
                  className={`p-1.5 rounded-md transition-colors ${
                    viewMode === 'list' ? 'bg-[#2A2F3A] text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <List className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>

          {activeNav === 'Credentials Vault' ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {CREDENTIALS.map((cred) => (
                <div
                  key={cred.id}
                  className="p-4 rounded-xl bg-[#181B20] border border-[#2A2F3A] flex items-center justify-between"
                >
                  <div className="flex items-center gap-3.5">
                    <div className="w-10 h-10 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
                      <KeyRound className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="text-sm font-medium text-white">{cred.label}</div>
                      <div className="text-xs font-mono text-slate-400">{cred.username}</div>
                      <div className="text-[11px] text-emerald-400 mt-0.5">{cred.method}</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] font-mono text-slate-500 block mb-2">Used {cred.lastUsed}</span>
                    <button
                      onClick={() => showToast(`Copied username ${cred.username} to clipboard`)}
                      className="px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 text-xs text-slate-300"
                    >
                      Copy ID
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ) : viewMode === 'grid' ? (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {filteredConnections.map((conn) => {
                const isWaking = wakingIds[conn.id];
                return (
                  <div
                    key={conn.id}
                    className="group rounded-xl bg-[#181B20] border border-[#2A2F3A] hover:border-blue-500/50 overflow-hidden transition-all duration-200 flex flex-col justify-between shadow-lg shadow-black/20"
                  >
                    <div
                      onClick={() => handleConnect(conn)}
                      className={`relative h-32 bg-gradient-to-br ${conn.wallpaper} p-3.5 flex flex-col justify-between cursor-pointer overflow-hidden`}
                    >
                      <div className="absolute inset-0 opacity-20 pointer-events-none p-4 flex items-center justify-center">
                        <div className="w-4/5 h-4/5 rounded border border-white/30 bg-black/30 p-2">
                          <div className="w-1/3 h-1.5 bg-white/40 rounded mb-1.5" />
                          <div className="w-2/3 h-1.5 bg-white/20 rounded" />
                        </div>
                      </div>

                      <div className="relative z-10 flex items-center justify-between">
                        <span className="px-2 py-0.5 rounded-md bg-black/50 backdrop-blur-md border border-white/10 text-[10px] font-medium text-slate-200">
                          {conn.os}
                        </span>
                        <div className="flex items-center gap-1.5">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setConnections((prev) =>
                                prev.map((c) => (c.id === conn.id ? { ...c, pinned: !c.pinned } : c))
                              );
                            }}
                            className={`p-1.5 rounded-lg backdrop-blur-md border border-white/10 transition-colors ${
                              conn.pinned
                                ? 'bg-amber-500/20 text-amber-300'
                                : 'bg-black/40 text-slate-400 hover:text-white'
                            }`}
                          >
                            <Star className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>

                      <div className="relative z-10 flex items-center justify-between">
                        <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-black/60 backdrop-blur-md text-[11px] font-mono">
                          <span className={`w-2 h-2 rounded-full ${getLatencyDot(conn.latency)}`} />
                          <span className={getLatencyColor(conn.latency)}>
                            {isWaking ? 'Waking...' : conn.status === 'sleeping' ? 'Asleep (WoL)' : `${conn.latency}ms`}
                          </span>
                        </div>

                        <span className="opacity-0 group-hover:opacity-100 transition-opacity px-3 py-1 rounded-lg bg-blue-600 text-white text-xs font-medium flex items-center gap-1 shadow-lg">
                          {conn.status === 'sleeping' ? (
                            <>
                              <Power className="w-3.5 h-3.5" /> Wake
                            </>
                          ) : (
                            <>
                              <Play className="w-3.5 h-3.5" /> Connect
                            </>
                          )}
                        </span>
                      </div>
                    </div>

                    <div className="p-4">
                      <div className="flex items-start justify-between gap-2 mb-2">
                        <div>
                          <h3 className="font-semibold text-sm text-white group-hover:text-blue-400 transition-colors">
                            {conn.name}
                          </h3>
                          <div className="font-mono text-xs text-slate-400 mt-0.5">
                            {conn.host}:{conn.port} <span className="text-slate-600">•</span> {conn.user}
                          </div>
                        </div>

                        <button
                          onClick={() => {
                            setDrawerTab('general');
                            setEditingConn({ ...conn });
                          }}
                          className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
                          title="Configure Connection"
                        >
                          <Settings className="w-4 h-4" />
                        </button>
                      </div>

                      <div className="flex items-center justify-between pt-3 border-t border-[#2A2F3A]/80 text-[11px] text-slate-500">
                        <span className="flex items-center gap-1.5">
                          <Folder className="w-3 h-3" />
                          {conn.folder}
                        </span>
                        <span className="font-mono text-[10px] text-slate-400">
                          {conn.monitors.length} {conn.monitors.length > 1 ? 'Monitors' : 'Monitor'} •{' '}
                          {conn.profile.toUpperCase()}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="rounded-xl bg-[#181B20] border border-[#2A2F3A] overflow-hidden">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#12151A] text-slate-400 border-b border-[#2A2F3A]">
                  <tr>
                    <th className="py-3 px-4 font-medium">Workspace</th>
                    <th className="py-3 px-4 font-medium">Host / Endpoint</th>
                    <th className="py-3 px-4 font-medium">OS</th>
                    <th className="py-3 px-4 font-medium">Telemetry</th>
                    <th className="py-3 px-4 font-medium text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#2A2F3A]/60">
                  {filteredConnections.map((conn) => (
                    <tr key={conn.id} className="hover:bg-white/[0.02] transition-colors">
                      <td className="py-3 px-4 font-medium text-white">{conn.name}</td>
                      <td className="py-3 px-4 font-mono text-slate-400">
                        {conn.host}:{conn.port}
                      </td>
                      <td className="py-3 px-4 text-slate-300">{conn.os}</td>
                      <td className="py-3 px-4 font-mono">
                        <span className={getLatencyColor(conn.latency)}>
                          {conn.status === 'sleeping' ? 'Asleep' : `${conn.latency}ms`}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right space-x-2">
                        <button
                          onClick={() => {
                            setDrawerTab('general');
                            setEditingConn({ ...conn });
                          }}
                          className="p-1.5 rounded hover:bg-white/10 text-slate-400 hover:text-white inline-flex"
                        >
                          <Settings className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => handleConnect(conn)}
                          className="px-3 py-1 rounded-md bg-blue-600 hover:bg-blue-500 text-white font-medium inline-flex items-center gap-1"
                        >
                          <Play className="w-3 h-3" /> Connect
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </main>

      {/* PRE-CONNECTION CONFIGURATION DRAWER */}
      {editingConn && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-lg bg-[#14171D] border-l border-[#2A2F3A] h-full flex flex-col justify-between shadow-2xl">
            <div>
              <div className="px-6 py-4 border-b border-[#2A2F3A] flex items-center justify-between">
                <div>
                  <h2 className="text-base font-semibold text-white">
                    {editingConn.isNew ? 'New Remote Workspace' : `Configure ${editingConn.name}`}
                  </h2>
                  <p className="text-xs text-slate-400 font-mono">{editingConn.host}</p>
                </div>
                <button
                  onClick={() => setEditingConn(null)}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/5"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="px-6 pt-3 border-b border-[#2A2F3A] flex gap-4 text-xs font-medium">
                {[
                  { id: 'general', label: 'General' },
                  { id: 'display', label: 'Display & Monitors' },
                  { id: 'resources', label: 'Local Resources' },
                  { id: 'performance', label: 'Performance' }
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setDrawerTab(tab.id)}
                    className={`pb-3 border-b-2 transition-colors ${
                      drawerTab === tab.id
                        ? 'border-blue-500 text-blue-400'
                        : 'border-transparent text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              <div className="p-6 space-y-5 overflow-y-auto max-h-[calc(100vh-190px)] text-xs">
                {drawerTab === 'general' && (
                  <>
                    <div>
                      <label className="block text-slate-400 mb-1.5">Friendly Workspace Name</label>
                      <input
                        type="text"
                        value={editingConn.name}
                        onChange={(e) => setEditingConn({ ...editingConn, name: e.target.value })}
                        className="w-full bg-[#0F1115] border border-[#2A2F3A] focus:border-blue-500 rounded-lg px-3 py-2 text-slate-100 outline-none"
                      />
                    </div>
                    <div className="grid grid-cols-3 gap-3">
                      <div className="col-span-2">
                        <label className="block text-slate-400 mb-1.5">Hostname / IPv4</label>
                        <input
                          type="text"
                          value={editingConn.host}
                          onChange={(e) => setEditingConn({ ...editingConn, host: e.target.value })}
                          className="w-full bg-[#0F1115] border border-[#2A2F3A] focus:border-blue-500 rounded-lg px-3 py-2 font-mono text-slate-100 outline-none"
                        />
                      </div>
                      <div>
                        <label className="block text-slate-400 mb-1.5">Port</label>
                        <input
                          type="number"
                          value={editingConn.port}
                          onChange={(e) => setEditingConn({ ...editingConn, port: Number(e.target.value) })}
                          className="w-full bg-[#0F1115] border border-[#2A2F3A] focus:border-blue-500 rounded-lg px-3 py-2 font-mono text-slate-100 outline-none"
                        />
                      </div>
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1.5">Username / Identity</label>
                      <input
                        type="text"
                        value={editingConn.user}
                        onChange={(e) => setEditingConn({ ...editingConn, user: e.target.value })}
                        className="w-full bg-[#0F1115] border border-[#2A2F3A] focus:border-blue-500 rounded-lg px-3 py-2 font-mono text-slate-100 outline-none"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1.5">Environment Folder</label>
                      <select
                        value={editingConn.folder}
                        onChange={(e) => setEditingConn({ ...editingConn, folder: e.target.value })}
                        className="w-full bg-[#0F1115] border border-[#2A2F3A] focus:border-blue-500 rounded-lg px-3 py-2 text-slate-100 outline-none"
                      >
                        <option value="Production Servers">Production Servers</option>
                        <option value="Home Lab">Home Lab</option>
                        <option value="Cloud VMs">Cloud VMs</option>
                      </select>
                    </div>
                  </>
                )}

                {drawerTab === 'display' && (
                  <>
                    <div>
                      <label className="block text-slate-400 mb-2">Multi-Monitor Topology Selector</label>
                      <p className="text-[11px] text-slate-500 mb-3">
                        Click physical displays below to span the remote desktop across selected monitors:
                      </p>
                      <div className="p-5 rounded-xl bg-[#0F1115] border border-[#2A2F3A] flex items-end justify-center gap-3">
                        {PHYSICAL_MONITORS.map((mon) => {
                          const selected = editingConn.monitors.includes(mon.id);
                          return (
                            <button
                              key={mon.id}
                              type="button"
                              onClick={() => toggleMonitorSelection(mon.id)}
                              className={`${mon.width} ${mon.height} rounded-lg border-2 flex flex-col items-center justify-center p-2 transition-all ${
                                selected
                                  ? 'bg-blue-500/20 border-blue-500 text-white shadow-lg shadow-blue-500/15'
                                  : 'bg-[#181B20] border-[#2A2F3A] text-slate-500 hover:border-slate-500'
                              }`}
                            >
                              <span className="font-mono font-bold text-sm">{mon.id}</span>
                              <span className="text-[9px] text-center leading-tight mt-0.5 opacity-80">
                                {mon.res.split('•')[0]}
                              </span>
                            </button>
                          );
                        })}
                      </div>
                      <div className="mt-2 text-[11px] font-mono text-blue-400">
                        Active Span: {editingConn.monitors.length} Display(s) Selected
                      </div>
                    </div>

                    <div>
                      <label className="block text-slate-400 mb-2">Resolution & DPI Scaling Mode</label>
                      <div className="space-y-2">
                        {[
                          { id: 'fit', title: 'Fit to Window (Dynamic EDID Resize)', desc: 'Reflows remote taskbar automatically on resize' },
                          { id: 'retina', title: 'Retina / HiDPI 200%', desc: 'Crisp fractional scaling for 4K/5K displays' },
                          { id: '1to1', title: 'Pixel-for-Pixel (1:1 Native)', desc: 'Zero interpolation blur for CAD/Design work' }
                        ].map((mode) => (
                          <div
                            key={mode.id}
                            onClick={() => setEditingConn({ ...editingConn, scaling: mode.id })}
                            className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                              editingConn.scaling === mode.id
                                ? 'bg-blue-500/15 border-blue-500 text-white'
                                : 'bg-[#0F1115] border-[#2A2F3A] text-slate-300 hover:border-slate-600'
                            }`}
                          >
                            <div className="font-medium">{mode.title}</div>
                            <div className="text-[11px] text-slate-400 mt-0.5">{mode.desc}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </>
                )}

                {drawerTab === 'resources' && (
                  <div className="space-y-3">
                    {[
                      { key: 'clipboard', label: 'Bidirectional Clipboard Sync', desc: 'Sync rich text, images, and copied files', icon: Clipboard },
                      { key: 'drives', label: 'Local Drives (Drag & Drop)', desc: 'Mount local Downloads folder as network drive', icon: HardDrive },
                      { key: 'audio', label: 'Remote Audio & Microphone', desc: '48kHz low-latency PCM audio passthrough', icon: Mic },
                      { key: 'smartcard', label: 'Smart Cards & YubiKey FIDO2', desc: 'Forward hardware security keys for remote auth', icon: KeyRound },
                      { key: 'usb', label: 'Raw USB Device Redirection', desc: 'Forward serial debuggers & peripherals', icon: Usb }
                    ].map((item) => {
                      const Icon = item.icon;
                      const enabled = editingConn.redirection[item.key];
                      return (
                        <div
                          key={item.key}
                          onClick={() =>
                            setEditingConn({
                              ...editingConn,
                              redirection: { ...editingConn.redirection, [item.key]: !enabled }
                            })
                          }
                          className="p-3 rounded-xl bg-[#0F1115] border border-[#2A2F3A] flex items-center justify-between cursor-pointer hover:border-slate-600"
                        >
                          <div className="flex items-center gap-3">
                            <Icon className={`w-4 h-4 ${enabled ? 'text-blue-400' : 'text-slate-500'}`} />
                            <div>
                              <div className="font-medium text-slate-200">{item.label}</div>
                              <div className="text-[11px] text-slate-500">{item.desc}</div>
                            </div>
                          </div>
                          <div
                            className={`w-9 h-5 rounded-full p-0.5 transition-colors ${
                              enabled ? 'bg-blue-600' : 'bg-[#2A2F3A]'
                            }`}
                          >
                            <div
                              className={`w-4 h-4 rounded-full bg-white transition-transform ${
                                enabled ? 'translate-x-4' : 'translate-x-0'
                              }`}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}

                {drawerTab === 'performance' && (
                  <div className="space-y-2.5">
                    {[
                      {
                        id: 'lan',
                        title: 'LAN Ultra (60 FPS • AVC 444)',
                        desc: 'Lossless text clarity, full desktop composition, UDP transport'
                      },
                      {
                        id: 'balanced',
                        title: 'Broadband Balanced (Adaptive)',
                        desc: 'Dynamic bitrate scaling between 5–25 Mbps with H.264'
                      },
                      {
                        id: 'low',
                        title: 'Cellular / Low Bandwidth',
                        desc: '16-bit color depth, disables wallpaper & window animations'
                      }
                    ].map((prof) => (
                      <div
                        key={prof.id}
                        onClick={() => setEditingConn({ ...editingConn, profile: prof.id })}
                        className={`p-3.5 rounded-xl border cursor-pointer transition-colors ${
                          editingConn.profile === prof.id
                            ? 'bg-blue-500/15 border-blue-500 text-white'
                            : 'bg-[#0F1115] border-[#2A2F3A] text-slate-300'
                        }`}
                      >
                        <div className="font-medium">{prof.title}</div>
                        <div className="text-[11px] text-slate-400 mt-1">{prof.desc}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <div className="px-6 py-4 border-t border-[#2A2F3A] bg-[#0F1115] flex items-center justify-end gap-2">
              <button
                onClick={() => setEditingConn(null)}
                className="px-4 py-2 rounded-lg bg-[#181B20] hover:bg-[#22262E] text-slate-300 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                onClick={saveConnectionConfig}
                className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium flex items-center gap-1.5"
              >
                <Check className="w-3.5 h-3.5" />
                Save Workspace
              </button>
            </div>
          </div>
        </div>
      )}

      {toast && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 px-4 py-2.5 rounded-xl bg-[#181B20] border border-[#2A2F3A] shadow-2xl text-xs text-slate-100">
          <span
            className={`w-2 h-2 rounded-full ${
              toast.type === 'success' ? 'bg-emerald-400' : 'bg-blue-400'
            }`}
          />
          {toast.message}
        </div>
      )}
    </div>
  );
}
