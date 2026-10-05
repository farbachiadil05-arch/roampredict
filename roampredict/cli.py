"""Command line: ``roampredict <command>``.

    doctor     check this laptop (read-only)
    scan       list nearby APs of your network with 802.11r/k/v flags (read-only)
    run        watch the signal; dry-run by default, --active to request switches
    report     measured switch times (recent vs never-used APs), predictions, learned paths
    simulate   compare strategies in the simulated school (any OS)
    latency    latency idle vs under load (bufferbloat), before/after a switch
    kill       stop all switching now (a running RoamPredict notices within 0.25 s)
    unkill     allow switching again
    forget     delete everything RoamPredict has learned
    paths      show where config, database, log and kill file live
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Sequence

from roampredict import __version__
from roampredict.config import AppConfig, ConfigError, find_config, load_config
from roampredict.safety import KillSwitch

__all__ = ["main", "build_parser"]


def _load(args: argparse.Namespace) -> AppConfig:
    path = find_config(getattr(args, "config", None))
    cfg = load_config(path)
    return cfg.with_interface(getattr(args, "interface", None))


def _need_windows(what: str) -> bool:
    if sys.platform == "win32":
        return True
    print(f"'{what}' needs Windows (wlanapi.dll). On this system you can run: roampredict simulate")
    return False


def _fmt_ms(value: float | None) -> str:
    return "-" if value is None else f"{value:.0f} ms"


# -- commands ---------------------------------------------------------------------------------


def cmd_doctor(args: argparse.Namespace) -> int:
    from roampredict.doctor import DoctorSettings, format_checks, run_doctor

    cfg = _load(args)
    settings = DoctorSettings(
        data_dir=cfg.paths.data_dir,
        kill_file=cfg.paths.kill_file,
        dry_run=cfg.safety.dry_run,
        allowed_ssids=cfg.safety.allowed_ssids,
        allowed_profiles=cfg.safety.allowed_profiles,
        interface=cfg.interface,
    )
    checks = run_doctor(settings)
    print(format_checks(checks))
    return 1 if any(c.status == "FAIL" for c in checks) else 0


def cmd_scan(args: argparse.Namespace) -> int:
    if not _need_windows("scan"):
        return 2
    from roampredict.platform.windows_wlan import WindowsWlanAdapter

    cfg = _load(args)
    with WindowsWlanAdapter(cfg.interface) as adapter:
        link = adapter.link_status()
        if args.fresh:
            adapter.request_scan(link.ssid if link.connected else None)
            if not adapter.wait_for_scan(cfg.executor.scan_timeout_s):
                print("(the scan did not complete in time - showing Windows' cached list)")
        entries = adapter.bss_list()
    if link.connected:
        print(f"Connected to '{link.ssid}' via {link.bssid} ({link.rssi_dbm:.0f} dBm, profile '{link.profile_name}', {link.auth})")
    shown = entries if args.all or not link.connected else [e for e in entries if e.ssid == link.ssid]
    shown.sort(key=lambda e: (e.ssid, -e.rssi_dbm))
    print(f"\n  {'':1} {'BSSID':<17} {'SSID':<20} {'ch':>4} {'band':>6} {'RSSI':>5} {'age':>6}  fast roaming")
    for e in shown:
        mark = "*" if link.connected and e.bssid == link.bssid else " "
        age = "-" if e.age_s is None else f"{e.age_s:.0f}s"
        ssid = (e.ssid or "(hidden)")[:20]
        print(f"  {mark} {e.bssid:<17} {ssid:<20} {e.channel or '-':>4} {e.band.value:>6} {e.rssi_dbm:>5.0f} {age:>6}  {e.capabilities.flags()}")
    print("\n'?' = the AP sent no information elements, so it cannot be detected here.")
    print("PMKSA (key) caching is never advertised; measure it with: roampredict report")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    cfg = _load(args)
    if args.active:
        cfg = cfg.with_active(True)
    kill = KillSwitch(cfg.paths.kill_file)
    if not cfg.safety.dry_run:
        if not cfg.safety.allowed_ssids:
            print("Refusing active mode: no SSIDs are allow-listed. Add them to [safety] allowed_ssids in the config.")
            return 2
        if kill.active():
            print(f"Refusing active mode: the kill switch is active ({kill.reason()}). Run: roampredict unkill")
            return 2
    if not _need_windows("run"):
        return 2
    from roampredict.engine import Engine
    from roampredict.net.l3 import WindowsNetworkOps
    from roampredict.net.latency import SOCKETS
    from roampredict.platform.windows_wlan import WindowsWlanAdapter
    from roampredict.roam.executor import RoamExecutor
    from roampredict.safety import SafetyGate
    from roampredict.telemetry import Telemetry
    from roampredict.topology.predictor import Predictor
    from roampredict.topology.store import TopologyStore

    telemetry = Telemetry(cfg.paths.log, console=True, verbose=args.verbose)
    adapter = WindowsWlanAdapter(cfg.interface)
    store = TopologyStore(cfg.paths.db)
    engine = None
    try:
        net = WindowsNetworkOps()
        engine = Engine(
            adapter=adapter,
            net=net,
            store=store,
            predictor=Predictor(store, cfg.predictor),
            executor=RoamExecutor(adapter, net, cfg.executor, telemetry, reset_sockets=SOCKETS.reset_all),
            safety=SafetyGate(cfg.safety, kill),
            telemetry=telemetry,
            filter_config=cfg.filter,
            trend_config=cfg.trend,
            sm_config=cfg.state,
            config=cfg.engine,
        )
        print(f"Log: {cfg.paths.log}   Stop with Ctrl+C.   Emergency stop from another window: roampredict kill")
        try:
            engine.run(duration_s=args.duration)
        except KeyboardInterrupt:
            print("\nstopped")
    finally:
        try:
            if engine is not None and engine.switches_ok and engine.last_requested_bssid:
                link = adapter.link_status()
                if link.connected and link.bssid == engine.last_requested_bssid:
                    print(
                        f"\nNote: you are still on {link.bssid}, which RoamPredict asked for by BSSID. Windows may keep\n"
                        "this connection on that AP (see README, Limits). If roaming seems stuck later, reconnect once:\n"
                        f'  netsh wlan connect name="{link.profile_name}"'
                    )
        except Exception:  # noqa: BLE001 - best effort note only
            pass
        adapter.close()
        store.close()
        telemetry.close()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from roampredict.topology.store import TopologyStore

    cfg = _load(args)
    if not cfg.paths.db.exists():
        print(f"No data yet ({cfg.paths.db} does not exist). Run 'roampredict run' for a while first.")
        return 0
    since = time.time() - args.days * 86400
    with TopologyStore(cfg.paths.db) as store:
        stats = store.switch_stats(since)
        switches = store.switches(since=since)
        transitions = store.all_transitions(limit=10)
    hours = cfg.predictor.recent_assoc_ttl_s / 3600
    print(f"Switch times, last {args.days} days (real switches only; 'recent' = associated within {hours:g} h)")
    if not stats:
        print("  none recorded yet")
    else:
        print(f"  {'who':<12} {'AP was':<9} {'n':>4} {'ok':>4} {'median':>9} {'p90':>9} {'median auth':>12}")
        for s in stats:
            print(
                f"  {s.initiator:<12} {s.candidate_class:<9} {s.n:>4} {s.ok:>4} {_fmt_ms(s.median_total_ms):>9} "
                f"{_fmt_ms(s.p90_total_ms):>9} {_fmt_ms(s.median_auth_ms):>12}"
            )
        print(
            "\n  How to read it: if 'recent' switches are clearly faster than 'never' ones, cached keys\n"
            "  (PMKSA caching) work on your network. If both are equally slow, the cache does not help\n"
            "  or expires sooner than the TTL - try a smaller ranking.recent_assoc_ttl_hours."
        )
    checks = [s for s in switches if s.initiator == "windows" and "hit" in s.detail]
    if checks:
        hits = sum(1 for s in checks if s.detail.get("hit"))
        leads = sorted(float(s.detail.get("lead_s", 0.0)) for s in checks)
        print(
            f"\nDry-run predictions checked against Windows' own roams: {hits}/{len(checks)} picked the same AP; "
            f"median {leads[len(leads) // 2]:.1f} s earlier than Windows."
        )
    if transitions:
        print("\nLearned 'usual next AP' (confirmed stays only):")
        for a, b, n, _ in transitions:
            print(f"  {a} -> {b}   x{n}")
    return 0


def cmd_simulate(args: argparse.Namespace) -> int:
    try:
        from simulator.run import main as simulate_main
    except ImportError:
        print("The simulator package is not installed. From the project folder run: pip install -e .[sim]")
        return 2
    argv = ["--seeds", str(args.seeds), "--ft", args.ft, "--plot", args.plot]
    for scenario in args.scenario or []:
        argv += ["--scenario", scenario]
    if args.no_plot:
        argv.append("--no-plot")
    return simulate_main(argv)


def cmd_latency(args: argparse.Namespace) -> int:
    from roampredict.net.latency import IcmpPinger, TcpPinger, bufferbloat_test, measure_latency

    target = args.target
    if target is None:
        if not _need_windows("latency without --target"):
            return 2
        from roampredict.net.l3 import WindowsNetworkOps
        from roampredict.platform.windows_wlan import WindowsWlanAdapter

        cfg = _load(args)
        with WindowsWlanAdapter(cfg.interface) as adapter:
            target = WindowsNetworkOps().snapshot(adapter.interface().guid).gateway
        if not target:
            print("No gateway found on the Wi-Fi adapter; pass --target HOST")
            return 2
    if args.tcp_port or sys.platform != "win32":
        pinger = TcpPinger(target, args.tcp_port or 443)
    else:
        pinger = IcmpPinger(target)
    print(f"Probing with {pinger.description} every 0.2 s")
    if args.url:
        print(f"{args.seconds:g} s idle, then {args.seconds:g} s while downloading {args.url} ...")
        result = bufferbloat_test(pinger, args.url, idle_s=args.seconds, load_s=args.seconds)
        print(f"  idle:   {result.idle.describe()}")
        print(f"  loaded: {result.loaded.describe()}")
        if result.download_mbps is not None:
            print(f"  download rate: {result.download_mbps:.1f} Mbit/s")
        if result.error:
            print(f"  download problem: {result.error}")
        print(f"  -> {result.verdict()}")
        print("  (Python cannot flush the Wi-Fi driver queue; this only measures it. Compare before/after a switch.)")
    else:
        stats = measure_latency(pinger, args.seconds)
        print(f"  {stats.describe()}")
    _explain_losses(pinger)
    return 0


def _explain_losses(pinger: object) -> None:
    failures = getattr(pinger, "failures", None)
    if not failures:
        return
    print("  why probes were lost:")
    for kind, n in failures.most_common():
        print(f"    {n:4d} x {kind}")
    if sum(failures.values()) and "timeout" in failures.most_common(1)[0][0]:
        print(
            "  hint: if ALL probes time out, the network probably blocks this address/port "
            "(campuses often block public DNS servers such as 1.1.1.1). Check it outside RoamPredict:\n"
            f"    Test-NetConnection {getattr(pinger, 'host', 'HOST')} -Port {getattr(pinger, 'port', 443)}\n"
            "  and try a target the campus allows, e.g. --target www.microsoft.com --tcp-port 443"
        )


def cmd_kill(args: argparse.Namespace) -> int:
    cfg = _load(args)
    KillSwitch(cfg.paths.kill_file).trip(args.reason)
    print(f"Kill switch set ({cfg.paths.kill_file}). RoamPredict will not request any switch until: roampredict unkill")
    return 0


def cmd_unkill(args: argparse.Namespace) -> int:
    cfg = _load(args)
    KillSwitch(cfg.paths.kill_file).clear()
    print("Kill switch cleared.")
    return 0


def cmd_forget(args: argparse.Namespace) -> int:
    from roampredict.topology.store import TopologyStore

    cfg = _load(args)
    if not args.yes:
        print(f"This deletes everything learned in {cfg.paths.db}. Repeat with --yes to confirm.")
        return 2
    if cfg.paths.db.exists():
        with TopologyStore(cfg.paths.db) as store:
            store.forget_all()
    print("Forgotten.")
    return 0


def cmd_paths(args: argparse.Namespace) -> int:
    cfg = _load(args)
    config = find_config(getattr(args, "config", None))
    print(f"config:    {config if config else f'{cfg.paths.config} (not created - using defaults)'}")
    print(f"data:      {cfg.paths.data_dir}")
    print(f"database:  {cfg.paths.db}")
    print(f"log:       {cfg.paths.log}")
    print(f"kill file: {cfg.paths.kill_file}{' (ACTIVE)' if cfg.paths.kill_file.exists() else ''}")
    return 0


# -- parser -----------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="roampredict",
        description="Predictive Wi-Fi roaming assistant for Windows 10/11 (dry-run by default).",
    )
    parser.add_argument("--version", action="version", version=f"roampredict {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name: str, func, help_text: str, *, config: bool = True, interface: bool = False) -> argparse.ArgumentParser:  # type: ignore[no-untyped-def]
        p = sub.add_parser(name, help=help_text, description=help_text)
        if config:
            p.add_argument("--config", help="config file (default: %%LOCALAPPDATA%%\\RoamPredict\\config.toml if present)")
        if interface:
            p.add_argument("--interface", help="Wi-Fi adapter GUID or part of its name")
        p.set_defaults(func=func)
        return p

    add("doctor", cmd_doctor, "check this laptop (read-only)", interface=True)
    p = add("scan", cmd_scan, "list nearby APs with 802.11r/k/v flags (read-only)", interface=True)
    p.add_argument("--fresh", action="store_true", help="ask Windows for a new scan first (takes up to ~4 s)")
    p.add_argument("--all", action="store_true", help="show every network, not only the one you are on")
    p = add("run", cmd_run, "watch the signal; dry-run unless --active", interface=True)
    p.add_argument("--active", action="store_true", help="really request switches (allow-listed SSIDs only)")
    p.add_argument("--duration", type=float, help="stop after this many seconds")
    p.add_argument("--verbose", action="store_true", help="print every sample")
    p = add("report", cmd_report, "measured switch times, prediction hits, learned paths")
    p.add_argument("--days", type=float, default=30.0, help="look back this many days (default 30)")
    p = add("simulate", cmd_simulate, "compare strategies in the simulated school (any OS)", config=False)
    p.add_argument("--seeds", type=int, default=10, help="random walks per scenario (default 10)")
    p.add_argument("--scenario", action="append", choices=("walk_out", "corner_seat", "hallway_pass"))
    p.add_argument("--ft", choices=("both", "on", "off"), default="both", help="802.11r on the simulated network")
    p.add_argument("--plot", default="roampredict_sim.png", help="output PNG")
    p.add_argument("--no-plot", action="store_true")
    p = add("latency", cmd_latency, "latency idle vs under load (bufferbloat)", interface=True)
    p.add_argument("--target", help="host to probe (default: the Wi-Fi gateway)")
    p.add_argument("--tcp-port", type=int, help="probe with TCP connects to this port instead of ICMP")
    p.add_argument("--url", help="large http(s) file to download as load, e.g. a campus mirror")
    p.add_argument("--seconds", type=float, default=10.0, help="duration of each phase (default 10)")
    p = add("kill", cmd_kill, "stop all switching now")
    p.add_argument("--reason", default="stopped by the user (roampredict kill)")
    add("unkill", cmd_unkill, "allow switching again")
    p = add("forget", cmd_forget, "delete everything RoamPredict has learned")
    p.add_argument("--yes", action="store_true", help="really delete")
    add("paths", cmd_paths, "show where config, database, log and kill file live")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001 - show a readable error instead of a traceback
        from roampredict.platform.base import WlanError

        if isinstance(exc, WlanError):
            print(f"Wi-Fi error: {exc}", file=sys.stderr)
            return 1
        raise


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
