#!/usr/bin/env python3
"""
capture.py — Screenshot and screen recording tool for WSL2 Arch Linux.

Supports:
  - Screenshots via scrot, grim, or Windows Snipping Tool
  - Screen recording via wf-recorder, ffmpeg, or Windows Game Bar
  - Auto-detects available tools and display server

Usage:
    python3 tools/capture.py screenshot [--output path.png]
    python3 tools/capture.py record [--duration 30] [--output path.mp4]
    python3 tools/capture.py stop          # Stop ongoing recording
    python3 tools/capture.py check         # Show available capture tools
"""

import argparse
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


def is_wsl() -> bool:
    try:
        return "microsoft" in Path("/proc/version").read_text().lower()
    except:
        return False


def is_wayland() -> bool:
    return os.environ.get("WAYLAND_DISPLAY") is not None


def is_x11() -> bool:
    return os.environ.get("DISPLAY") is not None


def has_tool(name: str) -> bool:
    return shutil.which(name) is not None


def win_cmd(cmd: str) -> int:
    """Run a command via powershell.exe from WSL."""
    return subprocess.call(["powershell.exe", "-NoProfile", "-Command", cmd])


def detect_tools() -> dict:
    """Detect available capture tools."""
    tools = {
        "wsl": is_wsl(),
        "wayland": is_wayland(),
        "x11": is_x11(),
        "screenshot": [],
        "record": [],
    }

    # Screenshot tools
    if has_tool("grim"):
        tools["screenshot"].append("grim")
    if has_tool("scrot"):
        tools["screenshot"].append("scrot")
    if has_tool("import"):  # ImageMagick
        tools["screenshot"].append("import")
    if is_wsl():
        tools["screenshot"].append("snippingtool (Windows)")

    # Recording tools
    if has_tool("wf-recorder"):
        tools["record"].append("wf-recorder")
    if has_tool("wl-screenrec"):
        tools["record"].append("wl-screenrec")
    if has_tool("ffmpeg"):
        if is_x11():
            tools["record"].append("ffmpeg-x11grab")
        if is_wayland():
            tools["record"].append("ffmpeg-pipewire")
    if is_wsl():
        tools["record"].append("xbox-game-bar (Windows)")

    return tools


def take_screenshot(output: str = None) -> str:
    """Take a screenshot using the best available tool."""
    if not output:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = f"evidence/screenshot_{ts}.png"

    Path(output).parent.mkdir(parents=True, exist_ok=True)

    if is_wayland() and has_tool("grim"):
        subprocess.run(["grim", output], check=True)
        print(f"📸 Screenshot saved: {output} (grim)")
        return output

    if is_x11() and has_tool("scrot"):
        subprocess.run(["scrot", output], check=True)
        print(f"📸 Screenshot saved: {output} (scrot)")
        return output

    if is_x11() and has_tool("import"):
        subprocess.run(["import", "-window", "root", output], check=True)
        print(f"📸 Screenshot saved: {output} (import)")
        return output

    if is_wsl():
        # Use PowerShell to capture screen on Windows side
        win_path = subprocess.check_output(
            ["wslpath", "-w", str(Path(output).resolve())]
        ).decode().strip()
        ps_script = f"""
Add-Type -AssemblyName System.Windows.Forms
$screen = [System.Windows.Forms.Screen]::PrimaryScreen
$bitmap = New-Object System.Drawing.Bitmap($screen.Bounds.Width, $screen.Bounds.Height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($screen.Bounds.Location, [System.Drawing.Point]::Empty, $screen.Bounds.Size)
$bitmap.Save('{win_path}')
$graphics.Dispose()
$bitmap.Dispose()
"""
        win_cmd(ps_script)
        print(f"📸 Screenshot saved: {output} (PowerShell)")
        return output

    print("❌ No screenshot tool available. Install grim (Wayland) or scrot (X11).", file=sys.stderr)
    sys.exit(1)


PID_FILE = "/tmp/capture_recording.pid"


def start_recording(output: str = None, duration: int = 0) -> str:
    """Start screen recording."""
    if not output:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = f"evidence/recording_{ts}.mp4"

    Path(output).parent.mkdir(parents=True, exist_ok=True)

    if is_wayland() and has_tool("wf-recorder"):
        cmd = ["wf-recorder", "-f", output]
        if duration > 0:
            cmd.extend(["--duration", str(duration)])
        proc = subprocess.Popen(cmd)
        Path(PID_FILE).write_text(str(proc.pid))
        print(f"🎬 Recording started: {output} (wf-recorder, PID {proc.pid})")
        if duration > 0:
            print(f"   Auto-stops in {duration}s")
        else:
            print(f"   Run `python3 tools/capture.py stop` to stop")
        return output

    if is_wayland() and has_tool("wl-screenrec"):
        cmd = ["wl-screenrec", "-f", output]
        proc = subprocess.Popen(cmd)
        Path(PID_FILE).write_text(str(proc.pid))
        print(f"🎬 Recording started: {output} (wl-screenrec, PID {proc.pid})")
        return output

    if has_tool("ffmpeg"):
        display = os.environ.get("DISPLAY", ":0")
        if is_wayland():
            # PipeWire capture for Wayland
            cmd = ["ffmpeg", "-f", "pipewire", "-i", "default",
                   "-c:v", "libx264", "-preset", "ultrafast", "-crf", "23"]
        else:
            # X11 capture
            cmd = ["ffmpeg", "-f", "x11grab", "-framerate", "30",
                   "-video_size", "1920x1080", "-i", display,
                   "-c:v", "libx264", "-preset", "ultrafast", "-crf", "23"]
        if duration > 0:
            cmd.extend(["-t", str(duration)])
        cmd.append(output)
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        Path(PID_FILE).write_text(str(proc.pid))
        print(f"🎬 Recording started: {output} (ffmpeg, PID {proc.pid})")
        return output

    if is_wsl():
        print("🎬 Opening Windows Xbox Game Bar for recording...")
        print("   Press Win+Alt+R to start/stop recording")
        print(f"   Recorded file will be in Windows Videos/Captures folder")
        print(f"   Copy it to: {output}")
        win_cmd("Start-Process 'ms-gamebar:'")
        return output

    print("❌ No recording tool available. Install wf-recorder or ffmpeg.", file=sys.stderr)
    sys.exit(1)


def stop_recording():
    """Stop an ongoing recording."""
    if not Path(PID_FILE).exists():
        print("No recording in progress.")
        return

    pid = int(Path(PID_FILE).read_text().strip())
    try:
        os.kill(pid, 2)  # SIGINT for graceful stop
        time.sleep(1)
        try:
            os.kill(pid, 0)  # Check if still running
            os.kill(pid, 9)  # Force kill
        except ProcessLookupError:
            pass
        print(f"⏹️  Recording stopped (PID {pid})")
    except ProcessLookupError:
        print(f"Process {pid} already stopped")
    finally:
        Path(PID_FILE).unlink(missing_ok=True)


def check_tools():
    """Display available capture tools."""
    tools = detect_tools()
    print("🔍 Capture Tool Detection")
    print(f"   WSL: {'Yes' if tools['wsl'] else 'No'}")
    print(f"   Wayland: {'Yes' if tools['wayland'] else 'No'}")
    print(f"   X11: {'Yes' if tools['x11'] else 'No'}")
    print(f"\n   Screenshot tools: {', '.join(tools['screenshot']) or 'None found'}")
    print(f"   Recording tools: {', '.join(tools['record']) or 'None found'}")

    if not tools["screenshot"]:
        print("\n   Install: sudo pacman -S grim (Wayland) or scrot (X11)")
    if not tools["record"]:
        print("   Install: sudo pacman -S wf-recorder (Wayland) or ffmpeg (X11)")


def main():
    parser = argparse.ArgumentParser(description="Screenshot and screen recording for WSL2")
    sub = parser.add_subparsers(dest="command")

    ss = sub.add_parser("screenshot", help="Take a screenshot")
    ss.add_argument("--output", "-o", help="Output file path")

    rec = sub.add_parser("record", help="Start screen recording")
    rec.add_argument("--output", "-o", help="Output file path")
    rec.add_argument("--duration", "-d", type=int, default=0, help="Duration in seconds (0=manual stop)")

    sub.add_parser("stop", help="Stop ongoing recording")
    sub.add_parser("check", help="Show available capture tools")

    args = parser.parse_args()

    if args.command == "screenshot":
        take_screenshot(args.output)
    elif args.command == "record":
        start_recording(args.output, args.duration)
    elif args.command == "stop":
        stop_recording()
    elif args.command == "check":
        check_tools()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
