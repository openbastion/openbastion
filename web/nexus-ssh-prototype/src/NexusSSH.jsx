import React, { useState, useEffect, useRef } from 'react';
import {
  Terminal,
  Server,
  Star,
  Folder,
  KeyRound,
  Shield,
  Search,
  Plus,
  Play,
  Settings,
  X,
  Check,
  LayoutGrid,
  List,
  PanelLeftClose,
  PanelLeftOpen,
  Globe,
  ArrowUpRight,
  Cpu,
  HardDrive,
  Activity,
  FolderOpen,
  FileCode,
  FileText,
  Download,
  Upload,
  Columns,
  Radio,
  Code2,
  Copy,
  RefreshCw,
  Lock,
  ArrowLeft,
  ChevronRight,
  Zap,
  Network
} from 'lucide-react';

const INITIAL_HOSTS = [
  {
    id: 'ssh-1',
    name: 'prod-api-gateway-01',
    host: '10.240.10.14',
    port: 22,
    user: 'deploy',
    distro: 'Ubuntu 24.04.1 LTS',
    arch: 'x86_64',
    folder: 'Production Cluster',
    pinned: true,
    status: 'online',
    latency: 11,
    keyLabel: 'ed25519-prod-ops',
    jumpHost: 'bastion-eu.nexus.internal',
    agentForwarding: true,
    moshEnabled: false,
    tunnels: [
      { id: 't1', type: 'Local (-L)', bind: '127.0.0.1:5432', target: 'db-master.internal:5432', active: true },
      { id: 't2', type: 'Local (-L)', bind: '127.0.0.1:9090', target: 'prometheus.internal:9090', active: false }
    ],
    stats: { cpu: '18%', ram: '4.2 / 16 GB', load: '0.42, 0.38, 0.31', uptime: '48d 14h' }
  },
  {
    id: 'ssh-2',
    name: 'k8s-worker-node-04',
    host: '10.240.12.88',
    port: 22,
    user: 'root',
    distro: 'Debian 12 (Bookworm)',
    arch: 'arm64',
    folder: 'Production Cluster',
    pinned: true,
    status: 'online',
    latency: 15,
    keyLabel: 'ed25519-prod-ops',
    jumpHost: 'bastion-eu.nexus.internal',
    agentForwarding: true,
    moshEnabled: false,
    tunnels: [
      { id: 't3', type: 'Dynamic (-D)', bind: '127.0.0.1:1080', target: 'SOCKS5 Proxy', active: true }
    ],
    stats: { cpu: '64%', ram: '24.8 / 32 GB', load: '2.14, 1.98, 1.85', uptime: '19d 06h' }
  },
  {
    id: 'ssh-3',
    name: 'edge-router-paris',
    host: '185.44.210.9',
    port: 2222,
    user: 'netops',
    distro: 'Alpine Linux 3.20',
    arch: 'x86_64',
    folder: 'Edge & Network',
    pinned: true,
    status: 'online',
    latency: 7,
    keyLabel: 'yubikey-fido2-sk',
    jumpHost: 'Direct TLS/SSH',
    agentForwarding: false,
    moshEnabled: true,
    tunnels: [],
    stats: { cpu: '6%', ram: '310 MB / 2 GB', load: '0.08, 0.05, 0.02', uptime: '142d 03h' }
  },
  {
    id: 'ssh-4',
    name: 'homelab-proxmox-01',
    host: '192.168.1.10',
    port: 22,
    user: 'admin',
    distro: 'Proxmox VE 8.3',
    arch: 'x86_64',
    folder: 'Home Lab',
    pinned: false,
    status: 'online',
    latency: 3,
    keyLabel: 'ed25519-personal',
    jumpHost: 'Direct (LAN)',
    agentForwarding: true,
    moshEnabled: true,
    tunnels: [
      { id: 't4', type: 'Local (-L)', bind: '127.0.0.1:8006', target: 'localhost:8006', active: true }
    ],
    stats: { cpu: '31%', ram: '48.0 / 64 GB', load: '1.12, 1.05, 0.94', uptime: '61d 22h' }
  },
  {
    id: 'ssh-5',
    name: 'gpu-train-h100',
    host: '34.118.40.192',
    port: 22,
    user: 'mlops',
    distro: 'Ubuntu 22.04 CUDA 12.4',
    arch: 'x86_64',
    folder: 'Cloud Instances',
    pinned: false,
    status: 'online',
    latency: 48,
    keyLabel: 'ed25519-cloud-ml',
    jumpHost: 'Tailscale Mesh',
    agentForwarding: true,
    moshEnabled: true,
    tunnels: [
      { id: 't5', type: 'Local (-L)', bind: '127.0.0.1:8888', target: 'localhost:8888', active: false }
    ],
    stats: { cpu: '89%', ram: '112 / 128 GB', load: '6.40, 5.90, 5.12', uptime: '4d 11h' }
  }
];

const SSH_KEYS = [
  { id: 'k1', name: 'ed25519-prod-ops', type: 'ED25519', fingerprint: 'SHA256:9xK2pL+mR8vQ4zW1nB7cT0yH6jF5dG3sA8eU2iO9pL0', protected: 'Passphrase + Agent' },
  { id: 'k2', name: 'yubikey-fido2-sk', type: 'ED25519-SK', fingerprint: 'SHA256:4mN8vB2xC7zL9kP1qW5eR3tY6uI0oP2aS4dF8gH1jK3', protected: 'Hardware Touch (FIDO2)' },
  { id: 'k3', name: 'ed25519-personal', type: 'ED25519', fingerprint: 'SHA256:7bV5cX2zN9mK4jH1gF6dS3aP8oI0uY7tR4eW2qQ9wE1', protected: 'macOS Keychain' },
  { id: 'k4', name: 'ed25519-cloud-ml', type: 'RSA-4096', fingerprint: 'SHA256:1qA2zW3sX4eD5cR6fV7tG8bY9hN0uJ1mI2kO3lP4pQ5', protected: 'Agent Loaded' }
];

const SNIPPETS = [
  { id: 's1', title: 'Docker: Running Containers', cmd: 'docker ps --format "table {{.Names}}\\t{{.Status}}\\t{{.Ports}}"' },
  { id: 's2', title: 'Systemd: Failed Units', cmd: 'systemctl --failed --no-pager' },
  { id: 's3', title: 'Disk & Inode Usage', cmd: 'df -hT | grep -v tmpfs' },
  { id: 's4', title: 'Active Listening Ports', cmd: 'ss -tulpn | grep LISTEN' },
  { id: 's5', title: 'Tail Nginx Error Logs', cmd: 'sudo tail -n 30 /var/log/nginx/error.log' }
];

const INITIAL_SFTP_FILES = [
  { name: 'docker-compose.prod.yml', type: 'file', size: '4.2 KB', perms: '-rw-r--r--', modified: '10:14' },
  { name: 'nginx', type: 'dir', size: '4.0 KB', perms: 'drwxr-xr-x', modified: 'Hier' },
  { name: 'scripts', type: 'dir', size: '4.0 KB', perms: 'drwxr-x---', modified: '18 Nov' },
  { name: '.env.production', type: 'file', size: '1.8 KB', perms: '-rw-------', modified: '14 Nov' },
  { name: 'deploy.sh', type: 'file', size: '3.1 KB', perms: '-rwxr-xr-x', modified: '12 Nov' }
];

export default function NexusSSH() {
  const [hosts, setHosts] = useState(INITIAL_HOSTS);
  const [activeNav, setActiveNav] = useState('All Hosts');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [viewMode, setViewMode] = useState('grid');
  const [searchQuery, setSearchQuery] = useState('');
  const [quickConnectInput, setQuickConnectInput] = useState('');
  const [sshAgentActive, setSshAgentActive] = useState(true);

  // Config Drawer
  const [editingHost, setEditingHost] = useState(null);
  const [drawerTab, setDrawerTab] = useState('connection');

  // Active Terminal Workspace
  const [openTabs, setOpenTabs] = useState([]);
  const [activeTabId, setActiveTabId] = useState(null);
  const [splitPaneHostId, setSplitPaneHostId] = useState(null);
  const [broadcastInput, setBroadcastInput] = useState(false);
  const [sftpOpen, setSftpOpen] = useState(false);
  const [snippetsOpen, setSnippetsOpen] = useState(false);
  const [tunnelsPopoverOpen, setTunnelsPopoverOpen] = useState(false);

  // Terminal Buffers per session ID
  const [terminalLogs, setTerminalLogs] = useState({});
  const [commandInputs, setCommandInputs] = useState({});
  const [sftpFiles, setSftpFiles] = useState(INITIAL_SFTP_FILES);
  const [toast, setToast] = useState(null);

  const searchInputRef = useRef(null);
  const terminalEndRef = useRef(null);

  const showToast = (message, type = 'info') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 3000);
  };

  // Cmd/Ctrl + K Shortcut
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (activeTabId) {
          setActiveTabId(null);
        }
        setTimeout(() => searchInputRef.current?.focus(), 50);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [activeTabId]);

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [terminalLogs, activeTabId]);

  const initSessionLogs = (host) => {
    if (terminalLogs[host.id]) return;
    setTerminalLogs((prev) => ({
      ...prev,
      [host.id]: [
        { type: 'system', text: `Connecting to ${host.host}:${host.port} via ${host.jumpHost}...` },
        { type: 'system', text: `Authenticated with key [${host.keyLabel}] (ED25519)` },
        { type: 'motd', text: `Welcome to ${host.distro} (${host.arch}) — Load: ${host.stats.load}` },
        { type: 'motd', text: `System uptime: ${host.stats.uptime} | Memory: ${host.stats.ram}` },
        { type: 'blank', text: '' }
      ]
    }));
  };

  const handleConnect = (host) => {
    initSessionLogs(host);
    if (!openTabs.some((t) => t.id === host.id)) {
      setOpenTabs((prev) => [...prev, host]);
    }
    setActiveTabId(host.id);
    setSnippetsOpen(false);
    setTunnelsPopoverOpen(false);
  };

  const handleQuickConnect = (e) => {
    e.preventDefault();
    if (!quickConnectInput.trim()) return;
    // Parse user@host:port
    const raw = quickConnectInput.trim();
    let user = 'root';
    let hostPart = raw;
    if (raw.includes('@')) {
      [user, hostPart] = raw.split('@');
    }
    const [ip, portStr] = hostPart.split(':');
    const newHost = {
      id: `quick-${Date.now()}`,
      name: ip,
      host: ip,
      port: Number(portStr) || 22,
      user,
      distro: 'Linux 6.8 Generic',
      arch: 'x86_64',
      folder: 'Quick Sessions',
      pinned: false,
      status: 'online',
      latency: 18,
      keyLabel: 'ed25519-prod-ops',
      jumpHost: 'Direct SSH',
      agentForwarding: true,
      moshEnabled: false,
      tunnels: [],
      stats: { cpu: '12%', ram: '2.1 / 8 GB', load: '0.15, 0.12, 0.10', uptime: '12d 04h' }
    };
    setQuickConnectInput('');
    handleConnect(newHost);
  };

  const handleCloseTab = (id) => {
    const remaining = openTabs.filter((t) => t.id !== id);
    setOpenTabs(remaining);
    if (splitPaneHostId === id) setSplitPaneHostId(null);
    if (activeTabId === id) {
      setActiveTabId(remaining.length > 0 ? remaining[remaining.length - 1].id : null);
    }
  };

  const executeCommandOnHost = (host, cmd) => {
    const trimmed = cmd.trim();
    const promptStr = `${host.user}@${host.name}:~$ ${trimmed}`;

    if (trimmed === 'clear') {
      setTerminalLogs((prev) => ({ ...prev, [host.id]: [] }));
      return;
    }

    let outputLines = [];
    if (!trimmed) {
      outputLines = [];
    } else if (trimmed === 'ls' || trimmed.startsWith('ls ')) {
      outputLines = ['docker-compose.prod.yml  nginx/  scripts/  deploy.sh'];
    } else if (trimmed === 'whoami') {
      outputLines = [host.user];
    } else if (trimmed === 'uptime') {
      outputLines = [` 22:48:12 up ${host.stats.uptime},  1 user,  load average: ${host.stats.load}`];
    } else if (trimmed.startsWith('df')) {
      outputLines = [
        'Filesystem     Type      Size  Used Avail Use% Mounted on',
        '/dev/nvme0n1p1 ext4      160G   48G  112G  30% /'
      ];
    } else if (trimmed.startsWith('docker ps')) {
      outputLines = [
        'NAMES               STATUS              PORTS',
        'nexus-api-core      Up 14 days          0.0.0.0:8080->8080/tcp',
        'redis-cache-01      Up 48 days          6379/tcp'
      ];
    } else if (trimmed.startsWith('ss ')) {
      outputLines = [
        'Netid  State   Recv-Q  Send-Q   Local Address:Port',
        'tcp    LISTEN  0       511            0.0.0.0:22',
        'tcp    LISTEN  0       4096           0.0.0.0:443'
      ];
    } else {
      outputLines = [`[exec] ${trimmed} -> exit status 0 (12ms)`];
    }

    setTerminalLogs((prev) => ({
      ...prev,
      [host.id]: [
        ...(prev[host.id] || []),
        { type: 'prompt', text: promptStr },
        ...outputLines.map((line) => ({ type: 'output', text: line }))
      ]
    }));
  };

  const handleTerminalSubmit = (e, targetHost) => {
    e.preventDefault();
    const cmd = commandInputs[targetHost.id] || '';
    if (broadcastInput && splitPaneHostId) {
      openTabs.forEach((t) => {
        if (t.id === activeTabId || t.id === splitPaneHostId) {
          executeCommandOnHost(t, cmd);
        }
      });
    } else {
      executeCommandOnHost(targetHost, cmd);
    }
    setCommandInputs((prev) => ({ ...prev, [targetHost.id]: '' }));
  };

  const toggleTunnel = (hostId, tunnelId) => {
    const updateList = (list) =>
      list.map((h) =>
        h.id === hostId
          ? {
              ...h,
              tunnels: h.tunnels.map((t) => (t.id === tunnelId ? { ...t, active: !t.active } : t))
            }
          : h
      );
    setHosts(updateList);
    setOpenTabs(updateList);
    showToast('Port forwarding rule updated', 'success');
  };

  const openNewHostDrawer = () => {
    setDrawerTab('connection');
    setEditingHost({
      id: `ssh-${Date.now()}`,
      name: 'staging-worker-02',
      host: '10.240.20.45',
      port: 22,
      user: 'ubuntu',
      distro: 'Ubuntu 24.04 LTS',
      arch: 'x86_64',
      folder: 'Production Cluster',
      pinned: false,
      status: 'online',
      latency: 14,
      keyLabel: 'ed25519-prod-ops',
      jumpHost: 'bastion-eu.nexus.internal',
      agentForwarding: true,
      moshEnabled: false,
      tunnels: [],
      stats: { cpu: '9%', ram: '1.8 / 8 GB', load: '0.11, 0.09, 0.08', uptime: '3d 18h' },
      isNew: true
    });
  };

  const saveHostConfig = () => {
    if (!editingHost) return;
    if (editingHost.isNew) {
      const { isNew, ...clean } = editingHost;
      setHosts((prev) => [clean, ...prev]);
      showToast(`Hôte "${clean.name}" ajouté`, 'success');
    } else {
      setHosts((prev) => prev.map((h) => (h.id === editingHost.id ? editingHost : h)));
      setOpenTabs((prev) => prev.map((t) => (t.id === editingHost.id ? editingHost : t)));
      showToast(`Configuration enregistrée pour ${editingHost.name}`, 'success');
    }
    setEditingHost(null);
  };

  const filteredHosts = hosts.filter((h) => {
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      h.name.toLowerCase().includes(q) ||
      h.host.toLowerCase().includes(q) ||
      h.distro.toLowerCase().includes(q) ||
      h.user.toLowerCase().includes(q);
    if (!matchesSearch) return false;
    if (activeNav === 'All Hosts') return true;
    if (activeNav === 'Pinned') return h.pinned;
    return h.folder === activeNav;
  });

  const activeHost = openTabs.find((t) => t.id === activeTabId);
  const splitHost = openTabs.find((t) => t.id === splitPaneHostId);

  const renderTerminalPane = (host, isSecondary = false) => {
    const logs = terminalLogs[host.id] || [];
    return (
      <div
        key={host.id}
        className={`flex-1 flex flex-col bg-[#0B0D10] overflow-hidden ${
          isSecondary ? 'border-l border-[#2A2F3A]' : ''
        }`}
      >
        {/* Pane Telemetry Strip */}
        <div className="h-8 px-4 bg-[#12151B] border-b border-[#2A2F3A]/80 flex items-center justify-between text-[11px] font-mono text-slate-400 shrink-0">
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1.5 text-emerald-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              {host.user}@{host.host}
            </span>
            <span className="text-slate-600">|</span>
            <span className="hidden sm:inline text-slate-400">Jump: {host.jumpHost}</span>
            {host.moshEnabled && (
              <span className="px-1.5 py-0.2 rounded bg-purple-500/15 text-purple-300 border border-purple-500/30 text-[10px]">
                MOSH UDP
              </span>
            )}
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden md:inline">CPU {host.stats.cpu}</span>
            <span className="hidden md:inline">RAM {host.stats.ram.split('/')[0]}</span>
            <span className="text-emerald-400">{host.latency}ms</span>
            {isSecondary && (
              <button
                onClick={() => setSplitPaneHostId(null)}
                className="text-slate-400 hover:text-white ml-1"
                title="Fermer le panneau scindé"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>

        {/* Terminal Output Stream */}
        <div className="flex-1 overflow-y-auto p-4 font-mono text-xs leading-relaxed space-y-1">
          {logs.map((entry, idx) => {
            if (entry.type === 'system') {
              return (
                <div key={idx} className="text-slate-500">
                  → {entry.text}
                </div>
              );
            }
            if (entry.type === 'motd') {
              return (
                <div key={idx} className="text-emerald-400/90">
                  {entry.text}
                </div>
              );
            }
            if (entry.type === 'prompt') {
              return (
                <div key={idx} className="text-slate-100 font-medium pt-1">
                  {entry.text}
                </div>
              );
            }
            return (
              <div key={idx} className="text-slate-300 whitespace-pre-wrap">
                {entry.text}
              </div>
            );
          })}
          <div ref={terminalEndRef} />
        </div>

        {/* Interactive Prompt Input */}
        <form
          onSubmit={(e) => handleTerminalSubmit(e, host)}
          className="px-4 py-2.5 bg-[#0F1115] border-t border-[#2A2F3A]/80 flex items-center gap-2 font-mono text-xs shrink-0"
        >
          <span className="text-emerald-400 shrink-0">
            {host.user}@{host.name}:~$
          </span>
          <input
            type="text"
            value={commandInputs[host.id] || ''}
            onChange={(e) => setCommandInputs((prev) => ({ ...prev, [host.id]: e.target.value }))}
            placeholder={
              broadcastInput && splitPaneHostId
                ? 'Mode Broadcast actif (envoi vers tous les terminaux ouverts)...'
                : 'Tapez une commande (ls, docker ps, df, ss, uptime, clear)...'
            }
            className="flex-1 bg-transparent text-slate-100 placeholder-slate-600 outline-none"
            autoFocus={!isSecondary}
          />
          {broadcastInput && splitPaneHostId && (
            <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 text-[10px]">
              BROADCAST
            </span>
          )}
        </form>
      </div>
    );
  };

  // ============================================================================
  // VIEW 2: ACTIVE SSH TERMINAL & SFTP WORKSPACE
  // ============================================================================
  if (activeHost) {
    return (
      <div className="h-screen w-screen bg-[#0B0D10] text-slate-100 flex flex-col overflow-hidden">
        {/* TOP TAB BAR & SESSION CONTROLS */}
        <header className="h-11 bg-[#12151B] border-b border-[#2A2F3A] px-2 flex items-center justify-between gap-2 shrink-0">
          {/* Left: Back to Hub + Open Session Tabs */}
          <div className="flex items-center gap-1 overflow-x-auto no-scrollbar">
            <button
              onClick={() => setActiveTabId(null)}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-xs text-slate-300 hover:text-white transition-colors shrink-0 mr-1"
              title="Retour au Hub SSH"
            >
              <ArrowLeft className="w-3.5 h-3.5 text-emerald-400" />
              <span className="hidden sm:inline">Hub</span>
            </button>

            {openTabs.map((tab) => {
              const isCurrent = tab.id === activeHost.id;
              return (
                <div
                  key={tab.id}
                  onClick={() => setActiveTabId(tab.id)}
                  className={`group flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs cursor-pointer transition-colors shrink-0 ${
                    isCurrent
                      ? 'bg-[#1D222B] text-white border border-[#2E3543]'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                  }`}
                >
                  <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  <span className="font-mono font-medium">{tab.name}</span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleCloseTab(tab.id);
                    }}
                    className="p-0.5 rounded hover:bg-white/10 text-slate-500 hover:text-rose-400"
                  >
                    <X className="w-3 h-3" />
                  </button>
                </div>
              );
            })}
          </div>

          {/* Right: Power Tools (Split Pane, Broadcast, Tunnels, Snippets, SFTP) */}
          <div className="flex items-center gap-1.5 shrink-0">
            {/* Split Terminal Toggle */}
            <button
              onClick={() => {
                if (splitPaneHostId) {
                  setSplitPaneHostId(null);
                  setBroadcastInput(false);
                } else {
                  const other = openTabs.find((t) => t.id !== activeHost.id) || hosts.find((h) => h.id !== activeHost.id);
                  if (other) {
                    initSessionLogs(other);
                    if (!openTabs.some((t) => t.id === other.id)) {
                      setOpenTabs((prev) => [...prev, other]);
                    }
                    setSplitPaneHostId(other.id);
                  }
                }
              }}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs border transition-colors ${
                splitPaneHostId
                  ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                  : 'bg-[#181B20] border-[#2A2F3A] text-slate-300 hover:text-white'
              }`}
              title="Scinder le terminal (Split View)"
            >
              <Columns className="w-3.5 h-3.5" />
              <span className="hidden md:inline">Split</span>
            </button>

            {/* Broadcast Input Toggle */}
            {splitPaneHostId && (
              <button
                onClick={() => {
                  setBroadcastInput(!broadcastInput);
                  showToast(!broadcastInput ? 'Saisie synchronisée activée' : 'Saisie synchronisée désactivée');
                }}
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs border transition-colors ${
                  broadcastInput
                    ? 'bg-amber-500/20 border-amber-500/40 text-amber-300'
                    : 'bg-[#181B20] border-[#2A2F3A] text-slate-400 hover:text-white'
                }`}
                title="Envoyer les commandes aux deux terminaux simultanément"
              >
                <Radio className="w-3.5 h-3.5" />
                <span className="hidden lg:inline">Broadcast</span>
              </button>
            )}

            {/* Port Forwarding / Tunnels Popover */}
            <div className="relative">
              <button
                onClick={() => {
                  setTunnelsPopoverOpen(!tunnelsPopoverOpen);
                  setSnippetsOpen(false);
                }}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[#181B20] border border-[#2A2F3A] text-xs text-slate-300 hover:text-white transition-colors"
              >
                <Network className="w-3.5 h-3.5 text-blue-400" />
                <span className="hidden md:inline">Tunnels</span>
                <span className="px-1.5 py-0.2 rounded bg-blue-500/20 text-blue-300 font-mono text-[10px]">
                  {activeHost.tunnels.filter((t) => t.active).length}
                </span>
              </button>

              {tunnelsPopoverOpen && (
                <div className="absolute right-0 top-9 w-80 rounded-xl bg-[#181B20] border border-[#2A2F3A] shadow-2xl p-3.5 z-50">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-semibold text-white">SSH Port Forwarding</span>
                    <span className="text-[10px] font-mono text-slate-400">{activeHost.name}</span>
                  </div>
                  {activeHost.tunnels.length === 0 ? (
                    <p className="text-xs text-slate-500 py-2">Aucun tunnel configuré pour cet hôte.</p>
                  ) : (
                    <div className="space-y-2">
                      {activeHost.tunnels.map((t) => (
                        <div
                          key={t.id}
                          className="p-2.5 rounded-lg bg-[#0F1115] border border-[#2A2F3A] flex items-center justify-between text-xs"
                        >
                          <div>
                            <div className="font-mono text-[11px] text-slate-200">{t.bind}</div>
                            <div className="font-mono text-[10px] text-slate-500">→ {t.target}</div>
                          </div>
                          <button
                            onClick={() => toggleTunnel(activeHost.id, t.id)}
                            className={`px-2 py-1 rounded text-[10px] font-mono ${
                              t.active
                                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                                : 'bg-white/5 text-slate-400'
                            }`}
                          >
                            {t.active ? 'ACTIF' : 'OFF'}
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Snippets Popover */}
            <div className="relative">
              <button
                onClick={() => {
                  setSnippetsOpen(!snippetsOpen);
                  setTunnelsPopoverOpen(false);
                }}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[#181B20] border border-[#2A2F3A] text-xs text-slate-300 hover:text-white transition-colors"
              >
                <Code2 className="w-3.5 h-3.5 text-amber-400" />
                <span className="hidden md:inline">Snippets</span>
              </button>

              {snippetsOpen && (
                <div className="absolute right-0 top-9 w-80 rounded-xl bg-[#181B20] border border-[#2A2F3A] shadow-2xl p-3 z-50">
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 mb-2">
                    Exécution rapide
                  </div>
                  <div className="space-y-1.5">
                    {SNIPPETS.map((snip) => (
                      <button
                        key={snip.id}
                        onClick={() => {
                          executeCommandOnHost(activeHost, snip.cmd);
                          setSnippetsOpen(false);
                        }}
                        className="w-full text-left p-2 rounded-lg bg-[#0F1115] hover:bg-white/5 border border-[#2A2F3A] transition-colors"
                      >
                        <div className="text-xs font-medium text-slate-200">{snip.title}</div>
                        <div className="text-[10px] font-mono text-emerald-400 truncate mt-0.5">{snip.cmd}</div>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* SFTP Browser Drawer Toggle */}
            <button
              onClick={() => setSftpOpen(!sftpOpen)}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs border transition-colors ${
                sftpOpen
                  ? 'bg-blue-500/20 border-blue-500/40 text-blue-300'
                  : 'bg-[#181B20] border-[#2A2F3A] text-slate-300 hover:text-white'
              }`}
            >
              <FolderOpen className="w-3.5 h-3.5 text-blue-400" />
              <span>SFTP</span>
            </button>
          </div>
        </header>

        {/* MAIN SPLIT CONTAINER: TERMINAL(S) + OPTIONAL SFTP BROWSER */}
        <div className="flex-1 flex overflow-hidden">
          <div className="flex-1 flex overflow-hidden">
            {renderTerminalPane(activeHost, false)}
            {splitHost && renderTerminalPane(splitHost, true)}
          </div>

          {/* INTEGRATED SFTP FILE EXPLORER DRAWER */}
          {sftpOpen && (
            <aside className="w-80 bg-[#12151B] border-l border-[#2A2F3A] flex flex-col shrink-0">
              <div className="px-4 py-2.5 border-b border-[#2A2F3A] flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs font-semibold text-white">
                  <HardDrive className="w-3.5 h-3.5 text-blue-400" />
                  <span>Explorateur SFTP</span>
                </div>
                <button onClick={() => setSftpOpen(false)} className="text-slate-400 hover:text-white">
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>

              <div className="px-4 py-2 bg-[#0B0D10] border-b border-[#2A2F3A] font-mono text-[11px] text-slate-400 flex items-center justify-between">
                <span className="truncate">/home/{activeHost.user}</span>
                <button
                  onClick={() => {
                    const uploaded = {
                      name: `config-backup-${Math.floor(10 + Math.random() * 89)}.tar.gz`,
                      type: 'file',
                      size: '12.4 MB',
                      perms: '-rw-r--r--',
                      modified: 'À l’instant'
                    };
                    setSftpFiles((prev) => [uploaded, ...prev]);
                    showToast(`Transféré ${uploaded.name} via SFTP`, 'success');
                  }}
                  className="flex items-center gap-1 px-2 py-0.5 rounded bg-blue-600 hover:bg-blue-500 text-white text-[10px] font-sans"
                >
                  <Upload className="w-3 h-3" /> Upload
                </button>
              </div>

              <div className="flex-1 overflow-y-auto p-2 space-y-1">
                {sftpFiles.map((file, i) => (
                  <div
                    key={i}
                    className="group flex items-center justify-between p-2 rounded-lg hover:bg-white/5 text-xs transition-colors"
                  >
                    <div className="flex items-center gap-2.5 truncate">
                      {file.type === 'dir' ? (
                        <Folder className="w-4 h-4 text-amber-400 shrink-0" />
                      ) : (
                        <FileCode className="w-4 h-4 text-slate-400 shrink-0" />
                      )}
                      <div className="truncate">
                        <div className="text-slate-200 font-mono text-[11px] truncate">{file.name}</div>
                        <div className="text-[10px] font-mono text-slate-500">
                          {file.perms} • {file.size}
                        </div>
                      </div>
                    </div>
                    {file.type === 'file' && (
                      <button
                        onClick={() => showToast(`Téléchargement SFTP : ${file.name}`, 'success')}
                        className="opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-white/10 text-slate-300"
                        title="Télécharger en local"
                      >
                        <Download className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </aside>
          )}
        </div>

        {toast && (
          <div className="fixed bottom-12 right-6 z-50 flex items-center gap-2.5 px-4 py-2 rounded-xl bg-[#181B20] border border-[#2A2F3A] shadow-2xl text-xs text-slate-100">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            {toast.message}
          </div>
        )}
      </div>
    );
  }

  // ============================================================================
  // VIEW 1: THE SSH HUB (INFRASTRUCTURE & INVENTORY)
  // ============================================================================
  return (
    <div className="min-h-screen bg-[#0F1115] text-slate-100 flex overflow-hidden">
      {/* LEFT SIDEBAR */}
      <aside
        className={`${
          sidebarCollapsed ? 'w-16' : 'w-64'
        } bg-[#0B0D10] border-r border-[#2A2F3A]/80 flex flex-col justify-between transition-all duration-200 shrink-0`}
      >
        <div>
          <div className="h-16 px-4 flex items-center justify-between border-b border-[#2A2F3A]/60">
            {!sidebarCollapsed && (
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-emerald-600 flex items-center justify-center shadow-lg shadow-emerald-600/20">
                  <Terminal className="w-4 h-4 text-white" />
                </div>
                <div>
                  <div className="font-semibold text-sm tracking-tight text-white">NexusSSH</div>
                  <div className="text-[10px] font-mono text-slate-500">v3.8 ZERO-TRUST</div>
                </div>
              </div>
            )}
            <button
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 transition-colors mx-auto"
            >
              {sidebarCollapsed ? <PanelLeftOpen className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
            </button>
          </div>

          <div className="p-3 space-y-1">
            {[
              { label: 'All Hosts', icon: Server, count: hosts.length },
              { label: 'Pinned', icon: Star, count: hosts.filter((h) => h.pinned).length }
            ].map((item) => {
              const Icon = item.icon;
              const active = activeNav === item.label;
              return (
                <button
                  key={item.label}
                  onClick={() => setActiveNav(item.label)}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                    active
                      ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/25'
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
                Clusters & Réseaux
              </div>
            )}
            <div className="space-y-1">
              {['Production Cluster', 'Edge & Network', 'Home Lab', 'Cloud Instances'].map((folder) => {
                const active = activeNav === folder;
                return (
                  <button
                    key={folder}
                    onClick={() => setActiveNav(folder)}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                      active
                        ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/25'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                    }`}
                  >
                    <Folder className="w-4 h-4 shrink-0 text-slate-500" />
                    {!sidebarCollapsed && <span className="truncate">{folder}</span>}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="px-3 pt-4">
            {!sidebarCollapsed && (
              <div className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                Cryptographie
              </div>
            )}
            <button
              onClick={() => setActiveNav('SSH Keychain')}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
                activeNav === 'SSH Keychain'
                  ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/25'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
              }`}
            >
              <KeyRound className="w-4 h-4 shrink-0" />
              {!sidebarCollapsed && <span>SSH Keychain</span>}
            </button>
          </div>
        </div>

        {/* SSH-Agent Status Card */}
        {!sidebarCollapsed && (
          <div className="p-3 m-3 rounded-xl bg-[#14171D] border border-[#2A2F3A]">
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-2 text-[11px] font-semibold text-slate-200">
                <Shield className="w-3.5 h-3.5 text-emerald-400" />
                <span>ssh-agent</span>
              </div>
              <button
                onClick={() => {
                  setSshAgentActive(!sshAgentActive);
                  showToast(!sshAgentActive ? 'ssh-agent déverrouillé (4 clés)' : 'ssh-agent verrouillé');
                }}
                className={`w-8 h-4 rounded-full transition-colors p-0.5 ${
                  sshAgentActive ? 'bg-emerald-500' : 'bg-[#2A2F3A]'
                }`}
              >
                <div
                  className={`w-3 h-3 rounded-full bg-white transition-transform ${
                    sshAgentActive ? 'translate-x-4' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>
            <p className="text-[10px] font-mono text-slate-500">
              {sshAgentActive ? '4 identités chargées en mémoire' : 'Agent verrouillé'}
            </p>
          </div>
        )}
      </aside>

      {/* MAIN WORKSPACE */}
      <main className="flex-1 flex flex-col h-screen overflow-hidden">
        <header className="h-16 px-6 border-b border-[#2A2F3A]/80 bg-[#0F1115]/90 backdrop-blur-md flex items-center justify-between gap-4 shrink-0">
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              ref={searchInputRef}
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Rechercher un serveur, IP, utilisateur ou OS..."
              className="w-full bg-[#181B20] border border-[#2A2F3A] focus:border-emerald-500 rounded-lg pl-9 pr-14 py-1.5 text-xs text-slate-100 placeholder-slate-500 outline-none transition-colors"
            />
            <span className="absolute right-2.5 top-1/2 -translate-y-1/2 px-1.5 py-0.5 rounded bg-[#0F1115] border border-[#2A2F3A] font-mono text-[10px] text-slate-400">
              ⌘K
            </span>
          </div>

          {/* Quick SSH URI Connect */}
          <form onSubmit={handleQuickConnect} className="hidden lg:flex items-center gap-2">
            <div className="relative">
              <Terminal className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={quickConnectInput}
                onChange={(e) => setQuickConnectInput(e.target.value)}
                placeholder="deploy@10.0.4.12:22"
                className="w-56 bg-[#181B20] border border-[#2A2F3A] focus:border-emerald-500 rounded-lg pl-8 pr-3 py-1.5 font-mono text-xs text-slate-200 placeholder-slate-500 outline-none"
              />
            </div>
            <button
              type="submit"
              className="px-3 py-1.5 rounded-lg bg-[#181B20] hover:bg-[#22262E] border border-[#2A2F3A] text-xs font-medium text-slate-200 flex items-center gap-1.5 transition-colors"
            >
              <ArrowUpRight className="w-3.5 h-3.5 text-emerald-400" />
              SSH Connect
            </button>
          </form>

          <button
            onClick={openNewHostDrawer}
            className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium flex items-center gap-1.5 shadow-lg shadow-emerald-600/20 transition-colors shrink-0"
          >
            <Plus className="w-4 h-4" />
            <span>Nouvel Hôte</span>
          </button>
        </header>

        {/* Active Sessions Banner */}
        {openTabs.length > 0 && (
          <div className="px-6 py-2 bg-emerald-500/10 border-b border-emerald-500/20 flex items-center justify-between text-xs">
            <span className="text-emerald-300 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              {openTabs.length} session(s) SSH active(s) en arrière-plan
            </span>
            <div className="flex items-center gap-2">
              {openTabs.map((t) => (
                <button
                  key={t.id}
                  onClick={() => setActiveTabId(t.id)}
                  className="px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-[11px]"
                >
                  {t.name}
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
                {activeNav === 'SSH Keychain'
                  ? 'Clés cryptographiques ED25519, RSA et jetons matériels FIDO2/YubiKey'
                  : 'Cliquez sur un serveur pour ouvrir un terminal multiplexé avec explorateur SFTP'}
              </p>
            </div>

            {activeNav !== 'SSH Keychain' && (
              <div className="flex items-center gap-1 bg-[#181B20] p-1 rounded-lg border border-[#2A2F3A]">
                <button
                  onClick={() => setViewMode('grid')}
                  className={`p-1.5 rounded-md ${
                    viewMode === 'grid' ? 'bg-[#2A2F3A] text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <LayoutGrid className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => setViewMode('list')}
                  className={`p-1.5 rounded-md ${
                    viewMode === 'list' ? 'bg-[#2A2F3A] text-white' : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <List className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>

          {activeNav === 'SSH Keychain' ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {SSH_KEYS.map((k) => (
                <div
                  key={k.id}
                  className="p-4 rounded-xl bg-[#181B20] border border-[#2A2F3A] flex items-center justify-between"
                >
                  <div className="flex items-center gap-3.5 min-w-0">
                    <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 shrink-0">
                      <KeyRound className="w-5 h-5" />
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold text-white">{k.name}</span>
                        <span className="px-1.5 py-0.5 rounded bg-white/5 font-mono text-[10px] text-emerald-400">
                          {k.type}
                        </span>
                      </div>
                      <div className="text-[11px] font-mono text-slate-400 truncate mt-0.5">{k.fingerprint}</div>
                      <div className="text-[11px] text-slate-500 mt-0.5">{k.protected}</div>
                    </div>
                  </div>
                  <button
                    onClick={() => showToast(`Empreinte publique copiée pour ${k.name}`)}
                    className="px-2.5 py-1.5 rounded-lg bg-white/5 hover:bg-white/10 text-xs text-slate-300 shrink-0 ml-3"
                  >
                    Copier PubKey
                  </button>
                </div>
              ))}
            </div>
          ) : viewMode === 'grid' ? (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {filteredHosts.map((host) => (
                <div
                  key={host.id}
                  className="group rounded-xl bg-[#181B20] border border-[#2A2F3A] hover:border-emerald-500/50 p-4 flex flex-col justify-between transition-all duration-200 shadow-lg shadow-black/20"
                >
                  <div>
                    <div className="flex items-start justify-between gap-2 mb-3">
                      <div className="flex items-center gap-2.5">
                        <div className="w-9 h-9 rounded-lg bg-[#0F1115] border border-[#2A2F3A] flex items-center justify-center text-emerald-400">
                          <Terminal className="w-4 h-4" />
                        </div>
                        <div>
                          <h3 className="font-mono font-semibold text-sm text-white group-hover:text-emerald-400 transition-colors">
                            {host.name}
                          </h3>
                          <div className="font-mono text-xs text-slate-400">
                            {host.user}@{host.host}:{host.port}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-1">
                        <button
                          onClick={() =>
                            setHosts((prev) =>
                              prev.map((h) => (h.id === host.id ? { ...h, pinned: !h.pinned } : h))
                            )
                          }
                          className={`p-1.5 rounded-lg transition-colors ${
                            host.pinned ? 'text-amber-400 bg-amber-500/10' : 'text-slate-500 hover:text-white'
                          }`}
                        >
                          <Star className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => {
                            setDrawerTab('connection');
                            setEditingHost({ ...host });
                          }}
                          className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/5"
                        >
                          <Settings className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>

                    {/* Live Server Telemetry Mini-Bar */}
                    <div className="grid grid-cols-3 gap-2 p-2.5 rounded-lg bg-[#0F1115] border border-[#2A2F3A]/80 font-mono text-[11px] mb-3">
                      <div>
                        <span className="text-slate-500 block text-[10px]">CPU</span>
                        <span className="text-slate-200">{host.stats.cpu}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">RAM</span>
                        <span className="text-slate-200">{host.stats.ram.split('/')[0]}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 block text-[10px]">PING</span>
                        <span className="text-emerald-400">{host.latency}ms</span>
                      </div>
                    </div>

                    <div className="flex flex-wrap gap-1.5 mb-4">
                      <span className="px-2 py-0.5 rounded bg-white/5 text-[10px] text-slate-300">
                        {host.distro}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-white/5 font-mono text-[10px] text-slate-400">
                        {host.keyLabel}
                      </span>
                      {host.tunnels.length > 0 && (
                        <span className="px-2 py-0.5 rounded bg-blue-500/15 text-blue-300 font-mono text-[10px]">
                          {host.tunnels.length} tunnel(s)
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="pt-3 border-t border-[#2A2F3A]/80 flex items-center justify-between">
                    <span className="text-[11px] text-slate-500 flex items-center gap-1.5">
                      <Folder className="w-3 h-3" />
                      {host.folder}
                    </span>

                    <button
                      onClick={() => handleConnect(host)}
                      className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium flex items-center gap-1.5 transition-colors"
                    >
                      <Play className="w-3 h-3" />
                      <span>Terminal</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-xl bg-[#181B20] border border-[#2A2F3A] overflow-hidden">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#12151A] text-slate-400 border-b border-[#2A2F3A]">
                  <tr>
                    <th className="py-3 px-4 font-medium">Hôte</th>
                    <th className="py-3 px-4 font-medium">Endpoint</th>
                    <th className="py-3 px-4 font-medium">Système</th>
                    <th className="py-3 px-4 font-medium">Latence</th>
                    <th className="py-3 px-4 font-medium text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#2A2F3A]/60">
                  {filteredHosts.map((host) => (
                    <tr key={host.id} className="hover:bg-white/[0.02]">
                      <td className="py-3 px-4 font-mono font-medium text-white">{host.name}</td>
                      <td className="py-3 px-4 font-mono text-slate-400">
                        {host.user}@{host.host}:{host.port}
                      </td>
                      <td className="py-3 px-4 text-slate-300">{host.distro}</td>
                      <td className="py-3 px-4 font-mono text-emerald-400">{host.latency}ms</td>
                      <td className="py-3 px-4 text-right space-x-2">
                        <button
                          onClick={() => {
                            setDrawerTab('connection');
                            setEditingHost({ ...host });
                          }}
                          className="p-1.5 rounded hover:bg-white/10 text-slate-400 hover:text-white inline-flex"
                        >
                          <Settings className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => handleConnect(host)}
                          className="px-3 py-1 rounded-md bg-emerald-600 hover:bg-emerald-500 text-white font-medium inline-flex items-center gap-1"
                        >
                          <Play className="w-3 h-3" /> SSH
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

      {/* CONFIGURATION DRAWER */}
      {editingHost && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-lg bg-[#14171D] border-l border-[#2A2F3A] h-full flex flex-col justify-between shadow-2xl">
            <div>
              <div className="px-6 py-4 border-b border-[#2A2F3A] flex items-center justify-between">
                <div>
                  <h2 className="text-base font-semibold text-white">
                    {editingHost.isNew ? 'Nouvel Hôte SSH' : `Configurer ${editingHost.name}`}
                  </h2>
                  <p className="text-xs font-mono text-slate-400">
                    {editingHost.user}@{editingHost.host}
                  </p>
                </div>
                <button
                  onClick={() => setEditingHost(null)}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-white/5"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="px-6 pt-3 border-b border-[#2A2F3A] flex gap-4 text-xs font-medium">
                {[
                  { id: 'connection', label: 'Connexion & Auth' },
                  { id: 'tunnels', label: 'Port Forwarding' },
                  { id: 'advanced', label: 'Bastion & Mosh' }
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setDrawerTab(tab.id)}
                    className={`pb-3 border-b-2 transition-colors ${
                      drawerTab === tab.id
                        ? 'border-emerald-500 text-emerald-400'
                        : 'border-transparent text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              <div className="p-6 space-y-4 text-xs overflow-y-auto max-h-[calc(100vh-180px)]">
                {drawerTab === 'connection' && (
                  <>
                    <div>
                      <label className="block text-slate-400 mb-1.5">Alias du serveur</label>
                      <input
                        type="text"
                        value={editingHost.name}
                        onChange={(e) => setEditingHost({ ...editingHost, name: e.target.value })}
                        className="w-full bg-[#0F1115] border border-[#2A2F3A] focus:border-emerald-500 rounded-lg px-3 py-2 font-mono text-slate-100 outline-none"
                      />
                    </div>
                    <div className="grid grid-cols-3 gap-3">
                      <div className="col-span-2">
                        <label className="block text-slate-400 mb-1.5">Adresse IP / FQDN</label>
                        <input
                          type="text"
                          value={editingHost.host}
                          onChange={(e) => setEditingHost({ ...editingHost, host: e.target.value })}
                          className="w-full bg-[#0F1115] border border-[#2A2F3A] focus:border-emerald-500 rounded-lg px-3 py-2 font-mono text-slate-100 outline-none"
                        />
                      </div>
                      <div>
                        <label className="block text-slate-400 mb-1.5">Port SSH</label>
                        <input
                          type="number"
                          value={editingHost.port}
                          onChange={(e) => setEditingHost({ ...editingHost, port: Number(e.target.value) })}
                          className="w-full bg-[#0F1115] border border-[#2A2F3A] focus:border-emerald-500 rounded-lg px-3 py-2 font-mono text-slate-100 outline-none"
                        />
                      </div>
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1.5">Utilisateur</label>
                      <input
                        type="text"
                        value={editingHost.user}
                        onChange={(e) => setEditingHost({ ...editingHost, user: e.target.value })}
                        className="w-full bg-[#0F1115] border border-[#2A2F3A] focus:border-emerald-500 rounded-lg px-3 py-2 font-mono text-slate-100 outline-none"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-400 mb-1.5">Clé privée SSH</label>
                      <select
                        value={editingHost.keyLabel}
                        onChange={(e) => setEditingHost({ ...editingHost, keyLabel: e.target.value })}
                        className="w-full bg-[#0F1115] border border-[#2A2F3A] focus:border-emerald-500 rounded-lg px-3 py-2 font-mono text-slate-100 outline-none"
                      >
                        {SSH_KEYS.map((k) => (
                          <option key={k.id} value={k.name}>
                            {k.name} ({k.type})
                          </option>
                        ))}
                      </select>
                    </div>
                  </>
                )}

                {drawerTab === 'tunnels' && (
                  <div className="space-y-3">
                    <p className="text-[11px] text-slate-400">
                      Redirections de ports locales (-L) ou dynamiques SOCKS5 (-D) montées automatiquement à la connexion :
                    </p>
                    {editingHost.tunnels.map((t, index) => (
                      <div key={t.id} className="p-3 rounded-xl bg-[#0F1115] border border-[#2A2F3A] space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-emerald-400">{t.type}</span>
                          <button
                            onClick={() =>
                              setEditingHost({
                                ...editingHost,
                                tunnels: editingHost.tunnels.filter((_, idx) => idx !== index)
                              })
                            }
                            className="text-slate-500 hover:text-rose-400"
                          >
                            <X className="w-3.5 h-3.5" />
                          </button>
                        </div>
                        <div className="font-mono text-slate-200">
                          {t.bind} → {t.target}
                        </div>
                      </div>
                    ))}
                    <button
                      type="button"
                      onClick={() =>
                        setEditingHost({
                          ...editingHost,
                          tunnels: [
                            ...editingHost.tunnels,
                            {
                              id: `tun-${Date.now()}`,
                              type: 'Local (-L)',
                              bind: '127.0.0.1:8080',
                              target: 'localhost:80',
                              active: true
                            }
                          ]
                        })
                      }
                      className="w-full py-2 rounded-lg border border-dashed border-emerald-500/40 text-emerald-400 hover:bg-emerald-500/10 font-medium"
                    >
                      + Ajouter une règle de tunnel
                    </button>
                  </div>
                )}

                {drawerTab === 'advanced' && (
                  <div className="space-y-4">
                    <div>
                      <label className="block text-slate-400 mb-1.5">ProxyJump / Bastion Host</label>
                      <input
                        type="text"
                        value={editingHost.jumpHost}
                        onChange={(e) => setEditingHost({ ...editingHost, jumpHost: e.target.value })}
                        className="w-full bg-[#0F1115] border border-[#2A2F3A] focus:border-emerald-500 rounded-lg px-3 py-2 font-mono text-slate-100 outline-none"
                      />
                    </div>
                    <div
                      onClick={() =>
                        setEditingHost({ ...editingHost, agentForwarding: !editingHost.agentForwarding })
                      }
                      className="p-3 rounded-xl bg-[#0F1115] border border-[#2A2F3A] flex items-center justify-between cursor-pointer"
                    >
                      <div>
                        <div className="font-medium text-slate-200">SSH Agent Forwarding (-A)</div>
                        <div className="text-[11px] text-slate-500">Transmettre les clés locales pour git/deploy</div>
                      </div>
                      <div
                        className={`w-9 h-5 rounded-full p-0.5 ${
                          editingHost.agentForwarding ? 'bg-emerald-600' : 'bg-[#2A2F3A]'
                        }`}
                      >
                        <div
                          className={`w-4 h-4 rounded-full bg-white transition-transform ${
                            editingHost.agentForwarding ? 'translate-x-4' : 'translate-x-0'
                          }`}
                        />
                      </div>
                    </div>
                    <div
                      onClick={() => setEditingHost({ ...editingHost, moshEnabled: !editingHost.moshEnabled })}
                      className="p-3 rounded-xl bg-[#0F1115] border border-[#2A2F3A] flex items-center justify-between cursor-pointer"
                    >
                      <div>
                        <div className="font-medium text-slate-200">Mosh (Mobile Shell UDP)</div>
                        <div className="text-[11px] text-slate-500">
                          Maintient la session en cas de changement d'IP / roaming
                        </div>
                      </div>
                      <div
                        className={`w-9 h-5 rounded-full p-0.5 ${
                          editingHost.moshEnabled ? 'bg-emerald-600' : 'bg-[#2A2F3A]'
                        }`}
                      >
                        <div
                          className={`w-4 h-4 rounded-full bg-white transition-transform ${
                            editingHost.moshEnabled ? 'translate-x-4' : 'translate-x-0'
                          }`}
                        />
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="px-6 py-4 border-t border-[#2A2F3A] bg-[#0F1115] flex items-center justify-end gap-2">
              <button
                onClick={() => setEditingHost(null)}
                className="px-4 py-2 rounded-lg bg-[#181B20] hover:bg-[#22262E] text-slate-300 text-xs font-medium"
              >
                Annuler
              </button>
              <button
                onClick={saveHostConfig}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium flex items-center gap-1.5"
              >
                <Check className="w-3.5 h-3.5" />
                Enregistrer
              </button>
            </div>
          </div>
        </div>
      )}

      {toast && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-2.5 px-4 py-2.5 rounded-xl bg-[#181B20] border border-[#2A2F3A] shadow-2xl text-xs text-slate-100">
          <span className="w-2 h-2 rounded-full bg-emerald-400" />
          {toast.message}
        </div>
      )}
    </div>
  );
}
