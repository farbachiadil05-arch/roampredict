"""RoamPredict Web Dashboard - Local Web Application.

Run with:
    py web_server.py [--port 8000] [--active]

Then open http://localhost:8000 in your browser.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

# Ensure local roampredict is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from roampredict.config import load_config, find_config
from roampredict.engine import Engine, EngineConfig
from roampredict.net.l3 import WindowsNetworkOps
from roampredict.net.latency import SOCKETS
from roampredict.platform.base import BssEntry, LinkStatus
from roampredict.platform.windows_wlan import WindowsWlanAdapter
from roampredict.roam.executor import RoamExecutor
from roampredict.safety import KillSwitch, SafetyGate
from roampredict.telemetry import Telemetry
from roampredict.topology.predictor import Predictor
from roampredict.topology.store import TopologyStore


class AppState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.is_running: bool = False
        self.mode: str = "dry-run"  # 'dry-run' or 'active'
        self.allowed_ssids: list[str] = []

        self.worker_thread: threading.Thread | None = None
        self.stop_event: threading.Event | None = None

        self.engine: Engine | None = None
        self.adapter: WindowsWlanAdapter | None = None
        self.store: TopologyStore | None = None
        self.telemetry: Telemetry | None = None

        self.last_link: dict[str, Any] = {}
        self.last_snapshot: dict[str, Any] = {}
        self.last_candidates: list[dict[str, Any]] = []
        self.ping_ms: float | None = None
        self.history: deque[dict[str, Any]] = deque(maxlen=60)  # ~15 seconds of history at 4Hz
        self.events: deque[dict[str, Any]] = deque(maxlen=100)
        self.switches_count: int = 0
        self.last_error: str | None = None


state = AppState()


class WebTelemetry(Telemetry):
    """Telemetry subclass that pushes records into memory for the web UI."""

    def __init__(self, target_queue: deque[dict[str, Any]], *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._target_queue = target_queue

    def emit(self, kind: str, message: str = "", **fields: Any) -> None:
        super().emit(kind, message, **fields)
        rec = {
            "time": time.strftime("%H:%M:%S"),
            "kind": kind,
            "message": message,
            **fields,
        }
        self._target_queue.append(rec)


def ping_gateway_bg() -> None:
    """Periodically ping the default gateway to report live latency."""
    net_ops = WindowsNetworkOps()
    while True:
        if state.is_running:
            try:
                gw = net_ops.default_gateway()
                if gw:
                    ms = net_ops.ping_gateway(gw, timeout_s=1.0)
                    with state.lock:
                        state.ping_ms = round(ms, 1) if ms is not None else None
            except Exception:
                pass
        time.sleep(1.5)


def worker_loop(mode: str) -> None:
    cfg_path = find_config(None)
    cfg = load_config(cfg_path)
    
    # If active mode requested in UI, enable active and allow current SSID
    is_active = (mode == "active")
    if is_active:
        cfg = cfg.with_active(True)
    else:
        cfg = cfg.with_active(False)

    kill = KillSwitch(cfg.paths.kill_file)
    telemetry = WebTelemetry(state.events, cfg.paths.log, console=True, keep_in_memory=True)
    
    adapter = None
    store = None
    try:
        adapter = WindowsWlanAdapter(cfg.interface)
        store = TopologyStore(cfg.paths.db)
        net = WindowsNetworkOps()

        # If active, allow current connected SSID automatically
        link_initial = adapter.link_status()
        if is_active and link_initial.connected and link_initial.ssid:
            if link_initial.ssid not in cfg.safety.allowed_ssids:
                allowed = list(cfg.safety.allowed_ssids) + [link_initial.ssid]
                cfg = cfg.with_allowed_ssids(allowed)

        safety_gate = SafetyGate(cfg.safety, kill)
        executor = RoamExecutor(adapter, net, cfg.executor, telemetry, reset_sockets=SOCKETS.reset_all)
        predictor = Predictor(store, cfg.predictor)

        engine = Engine(
            adapter=adapter,
            net=net,
            store=store,
            predictor=predictor,
            executor=executor,
            safety=safety_gate,
            telemetry=telemetry,
            filter_config=cfg.filter,
            trend_config=cfg.trend,
            sm_config=cfg.state,
            config=cfg.engine,
        )

        with state.lock:
            state.engine = engine
            state.adapter = adapter
            state.store = store
            state.telemetry = telemetry
            state.mode = mode
            state.last_error = None

        period = 1.0 / cfg.engine.sample_hz
        next_tick = adapter.now()

        while state.stop_event and not state.stop_event.is_set():
            now = adapter.now()
            try:
                engine.tick()
                link = adapter.link_status()
                snap = engine.last_snapshot
                bss_list = engine._bss

                snap_data = {}
                if snap:
                    raw_val = link.rssi_dbm if (link and link.rssi_dbm is not None) else snap.smoothed_dbm
                    slope_val = snap.trend.slope_dbm_s if (snap.trend and snap.trend.valid) else 0.0
                    ttt_val = snap.ttt_s if (snap.ttt_s and not math.isinf(snap.ttt_s)) else None
                    snap_data = {
                        "state": engine.sm.state.name,
                        "raw_dbm": round(raw_val, 1) if raw_val is not None else -80.0,
                        "filtered_dbm": round(snap.smoothed_dbm, 1),
                        "slope_dbm_per_s": round(slope_val, 2),
                        "time_to_threshold_s": round(ttt_val, 1) if ttt_val else None,
                        "bssid": link.bssid if link else None,
                        "ssid": link.ssid if link else None,
                    }

                link_data = {}
                if link:
                    link_data = {
                        "connected": link.connected,
                        "ssid": link.ssid,
                        "bssid": link.bssid,
                        "profile_name": link.profile_name,
                        "rssi_dbm": link.rssi_dbm,
                        "channel": link.channel,
                        "tx_rate_mbps": link.tx_rate_mbps,
                        "rx_rate_mbps": link.rx_rate_mbps,
                    }

                candidates_data = []
                for b in bss_list[:12]:
                    caps = b.capabilities
                    candidates_data.append({
                        "bssid": b.bssid,
                        "ssid": b.ssid,
                        "rssi_dbm": b.rssi_dbm,
                        "channel": b.channel,
                        "band": b.band.value if hasattr(b.band, "value") else str(b.band),
                        "has_11r": bool(caps.ft),
                        "has_11k": bool(caps.rrm_neighbor_report),
                        "has_11v": bool(caps.bss_transition),
                        "is_current": bool(link and b.bssid == link.bssid),
                    })

                with state.lock:
                    state.last_snapshot = snap_data
                    state.last_link = link_data
                    state.last_candidates = candidates_data
                    state.switches_count = engine.switches_ok
                    if snap:
                        state.history.append({
                            "t": round(now, 2),
                            "raw": raw_val,
                            "filtered": snap.smoothed_dbm,
                            "slope": slope_val,
                        })

            except Exception as exc:
                with state.lock:
                    state.last_error = str(exc)

            next_tick += period
            delay = next_tick - adapter.now()
            if delay > 0:
                adapter.sleep(delay)
            else:
                next_tick = adapter.now()

    except Exception as exc:
        with state.lock:
            state.last_error = f"Engine initialization error: {exc}"
    finally:
        with state.lock:
            state.is_running = False
            state.engine = None
        if adapter:
            adapter.close()
        if store:
            store.close()
        if telemetry:
            telemetry.close()


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RoamPredict - Wi-Fi Keep-Alive & Roaming Dashboard</title>
<style>
  :root {
    --bg-main: #0a0e17;
    --bg-card: #121826;
    --bg-card-hover: #182032;
    --border: #1f293d;
    --primary: #00f0ff;
    --primary-glow: rgba(0, 240, 255, 0.4);
    --secondary: #7928ca;
    --accent-green: #00ff88;
    --accent-orange: #ffaa00;
    --accent-red: #ff3366;
    --text-main: #f0f4f8;
    --text-muted: #8a99ad;
    --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg-main);
    color: var(--text-main);
    font-family: var(--font);
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    overflow-x: hidden;
  }

  /* Header */
  header {
    background: rgba(18, 24, 38, 0.8);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border);
    padding: 16px 32px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    position: sticky;
    top: 0;
    z-index: 100;
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 12px;
    font-weight: 800;
    font-size: 1.25rem;
    letter-spacing: -0.5px;
  }

  .logo-icon {
    width: 36px;
    height: 36px;
    border-radius: 10px;
    background: linear-gradient(135deg, var(--primary), var(--secondary));
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 0 20px var(--primary-glow);
  }

  .logo-icon svg { width: 22px; height: 22px; fill: white; }

  .header-actions {
    display: flex;
    align-items: center;
    gap: 16px;
  }

  .mode-selector {
    display: flex;
    background: #0d121d;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 3px;
  }

  .mode-btn {
    background: transparent;
    border: none;
    color: var(--text-muted);
    padding: 6px 14px;
    border-radius: 6px;
    font-size: 0.85rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s ease;
  }

  .mode-btn.active {
    background: var(--primary);
    color: #000;
    box-shadow: 0 0 12px var(--primary-glow);
  }

  /* Main Container */
  main {
    max-width: 1300px;
    margin: 0 auto;
    padding: 32px 24px;
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: 32px;
  }

  /* Hero GO Section */
  .hero-section {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 40px 20px;
    position: relative;
  }

  .go-button-container {
    position: relative;
    width: 220px;
    height: 220px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .pulse-ring {
    position: absolute;
    width: 100%;
    height: 100%;
    border-radius: 50%;
    background: radial-gradient(circle, var(--primary-glow) 0%, transparent 70%);
    animation: pulse 2.5s infinite;
    pointer-events: none;
  }

  @keyframes pulse {
    0% { transform: scale(0.9); opacity: 0.4; }
    50% { transform: scale(1.3); opacity: 0.8; }
    100% { transform: scale(0.9); opacity: 0.4; }
  }

  .btn-go {
    width: 180px;
    height: 180px;
    border-radius: 50%;
    border: 3px solid var(--primary);
    background: radial-gradient(circle at 30% 30%, #1a2538, #0b111e);
    color: var(--primary);
    font-size: 2.5rem;
    font-weight: 900;
    letter-spacing: 2px;
    cursor: pointer;
    box-shadow: 0 0 35px var(--primary-glow), inset 0 0 20px rgba(0, 240, 255, 0.2);
    transition: all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    z-index: 10;
  }

  .btn-go:hover {
    transform: scale(1.06);
    box-shadow: 0 0 50px var(--primary-glow), inset 0 0 30px rgba(0, 240, 255, 0.4);
    color: #fff;
  }

  .btn-go.running {
    border-color: var(--accent-red);
    color: var(--accent-red);
    box-shadow: 0 0 45px rgba(255, 51, 102, 0.5);
  }

  .btn-go.running:hover {
    transform: scale(1.06);
    color: #fff;
  }

  .btn-subtext {
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 1px;
    margin-top: 4px;
    opacity: 0.8;
  }

  .hero-subtitle {
    margin-top: 24px;
    color: var(--text-muted);
    font-size: 1rem;
    text-align: center;
    max-width: 500px;
  }

  /* Grid Layout */
  .grid-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
  }

  .grid-4 {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
  }

  @media (max-width: 900px) {
    .grid-2 { grid-template-columns: 1fr; }
    .grid-4 { grid-template-columns: 1fr 1fr; }
  }

  /* Cards */
  .card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 24px;
    position: relative;
    overflow: hidden;
  }

  .card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
  }

  .card-title {
    font-size: 0.95rem;
    font-weight: 700;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.8px;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .badge {
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
  }

  .badge-stable { background: rgba(0, 255, 136, 0.15); color: var(--accent-green); border: 1px solid var(--accent-green); }
  .badge-degrading { background: rgba(255, 170, 0, 0.15); color: var(--accent-orange); border: 1px solid var(--accent-orange); }
  .badge-roam-imminent { background: rgba(255, 51, 102, 0.15); color: var(--accent-red); border: 1px solid var(--accent-red); }
  .badge-offline { background: rgba(138, 153, 173, 0.15); color: var(--text-muted); border: 1px solid var(--border); }

  /* Stat Box */
  .stat-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .stat-label {
    font-size: 0.8rem;
    color: var(--text-muted);
    font-weight: 600;
    text-transform: uppercase;
  }

  .stat-value {
    font-size: 1.6rem;
    font-weight: 800;
    color: var(--text-main);
  }

  .stat-unit {
    font-size: 0.9rem;
    color: var(--text-muted);
    font-weight: 500;
    margin-left: 4px;
  }

  /* Gauge Container */
  .gauge-box {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 10px;
  }

  canvas#gaugeCanvas {
    max-width: 260px;
    max-height: 150px;
  }

  .gauge-value {
    font-size: 2.2rem;
    font-weight: 900;
    color: var(--primary);
    margin-top: -15px;
  }

  .gauge-desc {
    font-size: 0.85rem;
    color: var(--text-muted);
    margin-top: 4px;
  }

  /* Canvas Chart */
  .chart-box {
    width: 100%;
    height: 180px;
    position: relative;
  }

  canvas#signalChart {
    width: 100%;
    height: 100%;
  }

  /* Candidate Table */
  .candidate-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
  }

  .candidate-table th {
    text-align: left;
    color: var(--text-muted);
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    font-weight: 600;
    font-size: 0.75rem;
    text-transform: uppercase;
  }

  .candidate-table td {
    padding: 12px;
    border-bottom: 1px solid rgba(31, 41, 61, 0.5);
  }

  .current-ap-row {
    background: rgba(0, 240, 255, 0.05);
    border-left: 3px solid var(--primary);
  }

  .flag-badge {
    font-size: 0.7rem;
    padding: 2px 6px;
    border-radius: 4px;
    margin-right: 4px;
    background: rgba(255,255,255,0.06);
    color: var(--text-muted);
  }

  .flag-badge.active {
    background: rgba(0, 240, 255, 0.15);
    color: var(--primary);
    border: 1px solid rgba(0, 240, 255, 0.3);
  }

  /* Terminal Log */
  .terminal-box {
    background: #090c13;
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 14px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.8rem;
    height: 160px;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .log-line {
    display: flex;
    gap: 12px;
    line-height: 1.4;
  }

  .log-time { color: var(--text-muted); min-width: 65px; }
  .log-kind { color: var(--primary); font-weight: bold; min-width: 100px; text-transform: uppercase; }
  .log-msg { color: #d0d7de; word-break: break-all; }

  /* Status Bar */
  footer {
    margin-top: auto;
    border-top: 1px solid var(--border);
    background: var(--bg-card);
    padding: 12px 32px;
    font-size: 0.8rem;
    color: var(--text-muted);
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">
      <svg viewBox="0 0 24 24"><path d="M12 3C6.95 3 2.5 5.56 0 9.47L12 22 24 9.47C21.5 5.56 17.05 3 12 3M12 5.5C15.82 5.5 19.28 7.37 21.41 10.27L12 20.08 2.59 10.27C4.72 7.37 8.18 5.5 12 5.5Z"/></svg>
    </div>
    <span>RoamPredict <span style="font-weight:300; font-size: 0.85rem; color: var(--primary);">Web</span></span>
  </div>

  <div class="header-actions">
    <div class="mode-selector">
      <button class="mode-btn active" id="btnModeDry" onclick="setMode('dry-run')">Dry-Run (Monitor)</button>
      <button class="mode-btn" id="btnModeActive" onclick="setMode('active')">Keep Attached (Active)</button>
    </div>
    <span class="badge badge-offline" id="appStateBadge">STOPPED</span>
  </div>
</header>

<main>
  <!-- Hero GO Button -->
  <section class="hero-section">
    <div class="go-button-container">
      <div class="pulse-ring" id="pulseRing"></div>
      <button class="btn-go" id="mainGoBtn" onclick="toggleEngine()">
        <span id="btnText">GO</span>
        <span class="btn-subtext" id="btnSubtext">START ASSISTANT</span>
      </button>
    </div>
    <p class="hero-subtitle" id="heroSubtitle">
      Click <strong>GO</strong> to start tracking your Wi-Fi signal in real time and automatically optimize roaming before disconnects.
    </p>
  </section>

  <!-- 4 Stat Counters -->
  <div class="grid-4">
    <div class="stat-card">
      <span class="stat-label">Current SSID</span>
      <div class="stat-value" id="statSsid" style="font-size: 1.25rem;">--</div>
    </div>
    <div class="stat-card">
      <span class="stat-label">Gateway Ping</span>
      <div class="stat-value"><span id="statPing">--</span><span class="stat-unit">ms</span></div>
    </div>
    <div class="stat-card">
      <span class="stat-label">Degradation Rate</span>
      <div class="stat-value"><span id="statSlope">0.0</span><span class="stat-unit">dB/s</span></div>
    </div>
    <div class="stat-card">
      <span class="stat-label">Optimal Switches</span>
      <div class="stat-value"><span id="statSwitches">0</span><span class="stat-unit">handcrafted</span></div>
    </div>
  </div>

  <!-- Main Signal & Gauge Grid -->
  <div class="grid-2">
    <!-- Live Gauge Card -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Live Signal Strength</span>
        <span class="badge badge-offline" id="stateBadge">DISCONNECTED</span>
      </div>
      <div class="gauge-box">
        <canvas id="gaugeCanvas" width="300" height="170"></canvas>
        <div class="gauge-value" id="gaugeDbm">-- dBm</div>
        <div class="gauge-desc" id="gaugeDesc">Awaiting connection sample...</div>
      </div>
      <div style="margin-top: 16px; font-size: 0.85rem; color: var(--text-muted); display: flex; justify-content: space-between;">
        <span>Connected BSSID: <strong id="connBssid" style="color:var(--text-main);">--</strong></span>
        <span>Channel: <strong id="connChannel" style="color:var(--text-main);">--</strong></span>
      </div>
    </div>

    <!-- Live Chart Card -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Signal History (30s)</span>
        <span style="font-size: 0.75rem; color: var(--text-muted);">Threshold: -75 dBm</span>
      </div>
      <div class="chart-box">
        <canvas id="signalChart"></canvas>
      </div>
      <div style="margin-top: 12px; display: flex; gap: 16px; font-size: 0.75rem; color: var(--text-muted);">
        <span style="display:flex; align-items:center; gap:6px;"><span style="width:10px; height:2px; background:rgba(0, 240, 255, 0.4);"></span> Raw RSSI</span>
        <span style="display:flex; align-items:center; gap:6px;"><span style="width:10px; height:3px; background:#00f0ff;"></span> Filtered (Kalman)</span>
        <span style="display:flex; align-items:center; gap:6px;"><span style="width:10px; height:2px; background:#ff3366; border-top:1px dashed #ff3366;"></span> Roam Boundary (-75 dBm)</span>
      </div>
    </div>
  </div>

  <!-- Candidates Table & Event Feed -->
  <div class="grid-2">
    <!-- Visible Candidate APs -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Nearby Access Points</span>
        <span style="font-size:0.75rem; color:var(--text-muted);" id="candidateCount">0 discovered</span>
      </div>
      <div style="overflow-x: auto; max-height: 220px;">
        <table class="candidate-table">
          <thead>
            <tr>
              <th>BSSID</th>
              <th>SSID</th>
              <th>RSSI</th>
              <th>Ch / Band</th>
              <th>Features</th>
            </tr>
          </thead>
          <tbody id="candidateBody">
            <tr><td colspan="5" style="text-align:center; color:var(--text-muted);">No scan data yet. Click GO to start.</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Live Event Feed -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Live Telemetry & Decision Log</span>
        <span style="font-size:0.75rem; color:var(--text-muted);">Real-time stream</span>
      </div>
      <div class="terminal-box" id="terminalLog">
        <div class="log-line">
          <span class="log-time">--:--:--</span>
          <span class="log-kind">READY</span>
          <span class="log-msg">RoamPredict Web daemon initialized. Standing by.</span>
        </div>
      </div>
    </div>
  </div>
</main>

<footer>
  <span>RoamPredict v0.1.0 &bull; Native Windows 802.11 API</span>
  <span>Local interface at <code style="color:var(--primary);">http://localhost:8000</code></span>
</footer>

<script>
  let isRunning = false;
  let currentMode = 'dry-run';
  let historyData = [];

  function setMode(mode) {
    if (isRunning) {
      alert("Please STOP the assistant before changing mode.");
      return;
    }
    currentMode = mode;
    document.getElementById('btnModeDry').classList.toggle('active', mode === 'dry-run');
    document.getElementById('btnModeActive').classList.toggle('active', mode === 'active');
  }

  async function toggleEngine() {
    const btn = document.getElementById('mainGoBtn');
    btn.disabled = true;

    try {
      if (!isRunning) {
        // Start
        const res = await fetch('/api/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: currentMode })
        });
        const data = await res.json();
        if (data.status === 'ok') {
          isRunning = true;
          updateUIState(true);
        } else {
          alert("Error: " + (data.error || "Failed to start"));
        }
      } else {
        // Stop
        const res = await fetch('/api/stop', { method: 'POST' });
        const data = await res.json();
        isRunning = false;
        updateUIState(false);
      }
    } catch (e) {
      console.error(e);
      alert("Failed to communicate with local server: " + e.message);
    } finally {
      btn.disabled = false;
    }
  }

  function updateUIState(running) {
    const btn = document.getElementById('mainGoBtn');
    const btnText = document.getElementById('btnText');
    const btnSub = document.getElementById('btnSubtext');
    const badge = document.getElementById('appStateBadge');
    const subtitle = document.getElementById('heroSubtitle');
    const ring = document.getElementById('pulseRing');

    if (running) {
      btn.classList.add('running');
      btnText.textContent = 'STOP';
      btnSub.textContent = 'STOP ASSISTANT';
      badge.textContent = currentMode === 'active' ? 'KEEP ATTACHED' : 'MONITORING';
      badge.className = 'badge badge-stable';
      subtitle.innerHTML = currentMode === 'active' 
        ? '<strong>ACTIVE MODE:</strong> Actively monitoring and protecting your connection from Wi-Fi drops.'
        : '<strong>DRY-RUN MODE:</strong> Live signal monitoring and predicting handoffs without changing connection.';
      ring.style.animation = 'pulse 1s infinite';
    } else {
      btn.classList.remove('running');
      btnText.textContent = 'GO';
      btnSub.textContent = 'START ASSISTANT';
      badge.textContent = 'STOPPED';
      badge.className = 'badge badge-offline';
      subtitle.innerHTML = 'Click <strong>GO</strong> to start tracking your Wi-Fi signal in real time and automatically optimize roaming before disconnects.';
      ring.style.animation = 'pulse 2.5s infinite';
    }
  }

  // Draw analog gauge
  function drawGauge(dbm) {
    const canvas = document.getElementById('gaugeCanvas');
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    ctx.clearRect(0, 0, w, h);

    const cx = w / 2;
    const cy = h - 25;
    const radius = 110;

    // Background Arc (-100 dBm to -30 dBm)
    ctx.beginPath();
    ctx.arc(cx, cy, radius, Math.PI, 2 * Math.PI);
    ctx.lineWidth = 14;
    ctx.strokeStyle = '#1a2233';
    ctx.lineCap = 'round';
    ctx.stroke();

    if (dbm === null || isNaN(dbm)) return;

    // Clamp dbm between -95 and -35
    const minDbm = -95;
    const maxDbm = -35;
    const clamped = Math.max(minDbm, Math.min(maxDbm, dbm));
    const pct = (clamped - minDbm) / (maxDbm - minDbm);
    const angle = Math.PI + pct * Math.PI;

    // Color gradient based on signal quality
    let color = '#00ff88'; // great
    if (dbm < -75) color = '#ff3366'; // critical
    else if (dbm < -68) color = '#ffaa00'; // degrading

    // Active Arc
    ctx.beginPath();
    ctx.arc(cx, cy, radius, Math.PI, angle);
    ctx.lineWidth = 14;
    ctx.strokeStyle = color;
    ctx.shadowBlur = 15;
    ctx.shadowColor = color;
    ctx.lineCap = 'round';
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Needle
    ctx.save();
    ctx.translate(cx, cy);
    ctx.rotate(angle - Math.PI / 2);
    ctx.beginPath();
    ctx.moveTo(-4, 0);
    ctx.lineTo(0, -radius + 8);
    ctx.lineTo(4, 0);
    ctx.fillStyle = '#ffffff';
    ctx.fill();
    ctx.restore();

    // Center pin
    ctx.beginPath();
    ctx.arc(cx, cy, 7, 0, 2 * Math.PI);
    ctx.fillStyle = '#ffffff';
    ctx.fill();
  }

  // Draw Rolling Canvas Chart
  function drawChart(history) {
    const canvas = document.getElementById('signalChart');
    const ctx = canvas.getContext('2d');
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    const w = canvas.width;
    const h = canvas.height;

    ctx.clearRect(0, 0, w, h);
    if (!history || history.length < 2) return;

    const minD = -95;
    const maxD = -40;

    function getY(val) {
      const p = (val - minD) / (maxD - minD);
      return h - p * h;
    }

    // Threshold Line at -75 dBm
    const threshY = getY(-75);
    ctx.beginPath();
    ctx.setLineDash([4, 4]);
    ctx.moveTo(0, threshY);
    ctx.lineTo(w, threshY);
    ctx.strokeStyle = 'rgba(255, 51, 102, 0.7)';
    ctx.lineWidth = 1.5;
    ctx.stroke();
    ctx.setLineDash([]);

    const step = w / (history.length - 1);

    // Draw Raw RSSI (dotted / lighter line)
    ctx.beginPath();
    ctx.setLineDash([2, 3]);
    history.forEach((pt, i) => {
      const x = i * step;
      const y = getY(pt.raw);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = 'rgba(0, 240, 255, 0.4)';
    ctx.lineWidth = 1.5;
    ctx.stroke();
    ctx.setLineDash([]);

    // Draw Filtered RSSI (solid glowing line)
    ctx.beginPath();
    history.forEach((pt, i) => {
      const x = i * step;
      const y = getY(pt.filtered);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = '#00f0ff';
    ctx.lineWidth = 2.5;
    ctx.stroke();
  }

  // Poll status every 400 ms
  async function pollStatus() {
    try {
      const res = await fetch('/api/status');
      const data = await res.json();

      if (data.is_running !== isRunning) {
        isRunning = data.is_running;
        updateUIState(isRunning);
      }

      // Link Info
      if (data.link && data.link.connected) {
        document.getElementById('statSsid').textContent = data.link.ssid || '--';
        document.getElementById('connBssid').textContent = data.link.bssid || '--';
        document.getElementById('connChannel').textContent = (data.link.channel ? 'Ch ' + data.link.channel : '--');
      } else {
        document.getElementById('statSsid').textContent = 'Disconnected';
      }

      // Ping
      document.getElementById('statPing').textContent = (data.ping_ms !== null ? data.ping_ms : '--');

      // Switches
      document.getElementById('statSwitches').textContent = data.switches_count || 0;

      // Snapshot & State
      if (data.snapshot && data.snapshot.raw_dbm !== undefined) {
        const raw = data.snapshot.raw_dbm;
        const filtered = data.snapshot.filtered_dbm;
        const slope = data.snapshot.slope_dbm_per_s || 0;
        const stateName = data.snapshot.state || 'STABLE';

        document.getElementById('statSlope').textContent = slope.toFixed(1);
        document.getElementById('gaugeDbm').textContent = raw + ' dBm';
        drawGauge(raw);

        // Quality description
        let desc = 'Signal is strong and stable';
        if (raw < -80) desc = 'Critical: Connection drop likely!';
        else if (raw < -72) desc = 'Degrading: Roaming suggested';
        else if (raw < -65) desc = 'Moderate signal';
        document.getElementById('gaugeDesc').textContent = desc;

        // State Badge
        const stateBadge = document.getElementById('stateBadge');
        stateBadge.textContent = stateName;
        stateBadge.className = 'badge';
        if (stateName === 'STABLE') stateBadge.classList.add('badge-stable');
        else if (stateName === 'DEGRADING') stateBadge.classList.add('badge-degrading');
        else if (stateName === 'ROAM_IMMINENT') stateBadge.classList.add('badge-roam-imminent');
        else stateBadge.classList.add('badge-offline');
      } else {
        drawGauge(null);
      }

      // History chart
      if (data.history && data.history.length > 0) {
        drawChart(data.history);
      }

      // Candidates
      if (data.candidates) {
        document.getElementById('candidateCount').textContent = data.candidates.length + ' discovered';
        const tbody = document.getElementById('candidateBody');
        if (data.candidates.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--text-muted);">No APs found yet.</td></tr>';
        } else {
          tbody.innerHTML = data.candidates.map(c => `
            <tr class="${c.is_current ? 'current-ap-row' : ''}">
              <td style="font-family:monospace; font-weight:600;">${c.bssid} ${c.is_current ? '<span style="color:var(--primary);">★</span>' : ''}</td>
              <td>${c.ssid}</td>
              <td style="font-weight:700; color:${c.rssi_dbm < -75 ? 'var(--accent-red)' : 'var(--accent-green)'}">${c.rssi_dbm} dBm</td>
              <td>Ch ${c.channel} &bull; ${c.band}</td>
              <td>
                <span class="flag-badge ${c.has_11k ? 'active' : ''}">11k</span>
                <span class="flag-badge ${c.has_11v ? 'active' : ''}">11v</span>
                <span class="flag-badge ${c.has_11r ? 'active' : ''}">11r</span>
              </td>
            </tr>
          `).join('');
        }
      }

      // Logs
      if (data.events && data.events.length > 0) {
        const term = document.getElementById('terminalLog');
        term.innerHTML = data.events.slice(-20).map(e => `
          <div class="log-line">
            <span class="log-time">${e.time || ''}</span>
            <span class="log-kind">${e.kind || ''}</span>
            <span class="log-msg">${e.message || ''}</span>
          </div>
        `).join('');
        term.scrollTop = term.scrollHeight;
      }

    } catch (e) {
      console.error("Poll error", e);
    }
  }

  // Start polling
  setInterval(pollStatus, 400);
  pollStatus();
</script>
</body>
</html>
"""


class WebHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy standard HTTP access logs
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))
            return

        if parsed.path == "/api/status":
            with state.lock:
                data = {
                    "is_running": state.is_running,
                    "mode": state.mode,
                    "link": state.last_link,
                    "snapshot": state.last_snapshot,
                    "candidates": state.last_candidates,
                    "ping_ms": state.ping_ms,
                    "history": list(state.history),
                    "events": list(state.events),
                    "switches_count": state.switches_count,
                    "error": state.last_error,
                }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            payload = {}

        if parsed.path == "/api/start":
            mode = payload.get("mode", "dry-run")
            with state.lock:
                if state.is_running:
                    self._json_response({"status": "already_running"})
                    return
                state.is_running = True
                state.mode = mode
                state.stop_event = threading.Event()
                state.worker_thread = threading.Thread(target=worker_loop, args=(mode,), daemon=True)
                state.worker_thread.start()

            self._json_response({"status": "ok", "mode": mode})
            return

        if parsed.path == "/api/stop":
            with state.lock:
                if state.stop_event:
                    state.stop_event.set()
                state.is_running = False

            self._json_response({"status": "ok"})
            return

        self.send_response(404)
        self.end_headers()

    def _json_response(self, data: dict[str, Any], code: int = 200) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="RoamPredict Web Dashboard")
    parser.add_argument("--port", type=int, default=8000, help="Web server port (default: 8000)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    args = parser.parse_args()

    # Start gateway ping background thread
    t_ping = threading.Thread(target=ping_gateway_bg, daemon=True)
    t_ping.start()

    server = ThreadingHTTPServer((args.host, args.port), WebHandler)
    url = f"http://{args.host}:{args.port}"
    print(f"\n=======================================================")
    print(f"  RoamPredict Web Dashboard is RUNNING!")
    print(f"  Open your browser at: {url}")
    print(f"=======================================================\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping web server...")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
