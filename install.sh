#!/bin/sh
# Install (or reinstall) pkgdash: the dashboard service and its menu bar icon, as per-user
# LaunchAgents that start at login.
# Usage: ./install.sh            install / restart (re-run after editing any source file)
#        ./install.sh uninstall  stop and remove both (state in ~/.local/share/pkgdash is kept)
set -eu
LABEL=com.adam.pkgdash
MENU_LABEL=com.adam.pkgdash.menu
DIR=$(cd "$(dirname "$0")" && pwd)
AGENTS="$HOME/Library/LaunchAgents"
STATE="$HOME/.local/share/pkgdash"
APP="$HOME/Applications/pkgdash.app"
GUI="gui/$(id -u)"

launchctl bootout "$GUI/$LABEL" 2>/dev/null || true
launchctl bootout "$GUI/$MENU_LABEL" 2>/dev/null || true
# bootout returns before the jobs are gone, and loading them again too soon fails ("Bootstrap failed: 5")
for _ in $(seq 30); do
  { launchctl print "$GUI/$LABEL" || launchctl print "$GUI/$MENU_LABEL"; } >/dev/null 2>&1 || break
  sleep 1
done

if [ "${1:-}" = "uninstall" ]; then
  rm -f "$AGENTS/$LABEL.plist" "$AGENTS/$MENU_LABEL.plist"
  rm -rf "$APP"
  echo "pkgdash removed"
  exit 0
fi

# --- dashboard service -------------------------------------------------------
# launchd agents can't read protected folders like ~/Documents (TCC), so run from a copy in the state dir
mkdir -p "$STATE/app"
cp "$DIR/server.py" "$DIR/index.html" "$STATE/app/"
cat > "$AGENTS/$LABEL.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/python3</string>
    <string>-I</string>
    <string>$STATE/app/server.py</string>
  </array>
  <key>WorkingDirectory</key><string>$STATE</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$STATE/service.log</string>
  <key>StandardErrorPath</key><string>$STATE/service.log</string>
</dict>
</plist>
EOF
launchctl bootstrap "$GUI" "$AGENTS/$LABEL.plist"

# --- menu bar icon -----------------------------------------------------------
# Only rebuilt when its source (or this script) changes: it's ad-hoc signed, so every rebuild
# looks like a new app to macOS and it would ask for access to the projects folder again.
BIN="$APP/Contents/MacOS/pkgdash"
if [ ! -x "$BIN" ] || [ "$DIR/menubar/PkgdashMenu.swift" -nt "$BIN" ] || [ "$0" -nt "$BIN" ]; then
mkdir -p "$APP/Contents/MacOS"
swiftc -O -target arm64-apple-macos13 -framework AppKit \
  -o "$BIN" "$DIR/menubar/PkgdashMenu.swift"
cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>$MENU_LABEL</string>
  <key>CFBundleName</key><string>pkgdash</string>
  <key>CFBundleExecutable</key><string>pkgdash</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSUIElement</key><true/>
  <key>NSAppTransportSecurity</key><dict><key>NSAllowsLocalNetworking</key><true/></dict>
  <key>NSDocumentsFolderUsageDescription</key><string>pkgdash reads the lockfiles of your projects (package-lock.json, uv.lock, Cargo.lock…) to check their dependencies for malware and vulnerabilities.</string>
  <key>NSDesktopFolderUsageDescription</key><string>pkgdash reads the lockfiles of your projects (package-lock.json, uv.lock, Cargo.lock…) to check their dependencies for malware and vulnerabilities.</string>
  <key>NSDownloadsFolderUsageDescription</key><string>pkgdash reads the lockfiles of your projects (package-lock.json, uv.lock, Cargo.lock…) to check their dependencies for malware and vulnerabilities.</string>
</dict>
</plist>
EOF
codesign --force --sign - "$APP" >/dev/null 2>&1
fi
# KeepAlive only on crash, so "Quit Menu Icon" stays quit until next login
cat > "$AGENTS/$MENU_LABEL.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$MENU_LABEL</string>
  <key>ProgramArguments</key><array><string>$APP/Contents/MacOS/pkgdash</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
  <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
EOF
launchctl bootstrap "$GUI" "$AGENTS/$MENU_LABEL.plist"

echo "pkgdash running → http://127.0.0.1:7878 (menu bar icon: left-click opens, right-click for menu)"
