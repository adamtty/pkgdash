#!/bin/bash
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
BIN="$APP/Contents/MacOS/pkgdash"
GUI="gui/$(id -u)"

step() { printf '==> %s\n' "$*"; }
fail() { printf 'pkgdash: %s\n' "$*" >&2; exit 1; }

# The menu bar app is only rebuilt when its source (or this script) changes: it's ad-hoc signed, so every
# rebuild looks like a new app to macOS and it would ask for access to the projects folder again.
NEED_BUILD=0
if [ ! -x "$BIN" ] || [ "$DIR/menubar/PkgdashMenu.swift" -nt "$BIN" ] || [ "$0" -nt "$BIN" ]; then
  NEED_BUILD=1
fi

# check what's needed before stopping anything, so a failed install leaves a running pkgdash alone
if [ "${1:-}" != "uninstall" ]; then
  [ "$(uname -m)" = arm64 ] || fail "needs a Mac with Apple Silicon (this one is $(uname -m))"
  if ! xcode-select -p >/dev/null 2>&1 || ! /usr/bin/python3 -c "" >/dev/null 2>&1; then
    fail "needs the Xcode Command Line Tools for /usr/bin/python3 and swiftc: run xcode-select --install, then try again"
  fi
  if [ "$NEED_BUILD" = 1 ] && ! xcrun --find swiftc >/dev/null 2>&1; then
    fail "can't find swiftc to build the menu bar app: run xcode-select --install, then try again"
  fi
fi

step "Stopping the running service and menu bar app (if any)"
launchctl bootout "$GUI/$LABEL" 2>/dev/null || true
launchctl bootout "$GUI/$MENU_LABEL" 2>/dev/null || true
# bootout returns before the jobs are gone, and loading them again too soon fails ("Bootstrap failed: 5")
waited=0
for _ in $(seq 30); do
  { launchctl print "$GUI/$LABEL" || launchctl print "$GUI/$MENU_LABEL"; } >/dev/null 2>&1 || break
  printf '.'
  waited=1
  sleep 1
done
if [ "$waited" = 1 ]; then echo; fi

if [ "${1:-}" = "uninstall" ]; then
  step "Removing the LaunchAgents and $APP"
  rm -f "$AGENTS/$LABEL.plist" "$AGENTS/$MENU_LABEL.plist"
  rm -rf "$APP"
  echo "pkgdash removed (state in $STATE is kept)"
  exit 0
fi

# --- dashboard service -------------------------------------------------------
# launchd agents can't read protected folders like ~/Documents (TCC), so run from a copy in the state dir
step "Installing the dashboard service into $STATE/app"
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
step "Starting the dashboard service"
launchctl bootstrap "$GUI" "$AGENTS/$LABEL.plist"

# --- menu bar icon -----------------------------------------------------------
if [ "$NEED_BUILD" = 1 ]; then
step "Building the menu bar app (swiftc, can take a minute)"
mkdir -p "$APP/Contents/MacOS"
swiftc -O -target arm64-apple-macos13 -framework AppKit \
  -o "$BIN" "$DIR/menubar/PkgdashMenu.swift" || fail "swiftc couldn't build menubar/PkgdashMenu.swift (see above)"
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
# hardened runtime: macOS ignores DYLD_* variables (e.g. planted in the LaunchAgent), so no other code
# can be loaded into the app that holds the projects-folder permission
step "Signing the menu bar app (ad-hoc, hardened runtime)"
if ! out=$(codesign --force --options runtime --sign - "$APP" 2>&1); then
  rm -f "$BIN"  # so the next run rebuilds and signs it again
  fail "codesign failed: $out"
fi
else
step "Menu bar app unchanged, not rebuilding it"
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
step "Starting the menu bar app"
launchctl bootstrap "$GUI" "$AGENTS/$MENU_LABEL.plist"

echo "pkgdash running → http://127.0.0.1:7878 (menu bar icon: left-click opens, right-click for menu)"
