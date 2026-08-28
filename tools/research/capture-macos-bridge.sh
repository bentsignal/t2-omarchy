#!/bin/bash
set -euo pipefail

if [[ $(uname -s) != Darwin ]]; then
  echo "This collector must be run from macOS." >&2
  exit 2
fi
if (( $# != 1 )); then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 2
fi

capture_dir=$1
mkdir -p "$capture_dir/files"

sw_vers >"$capture_dir/sw_vers.txt"
uname -a >"$capture_dir/uname.txt"

copy_if_readable() {
  source_path=$1
  destination_name=$2
  if [[ -r $source_path && -f $source_path ]]; then
    /bin/cp -p "$source_path" "$capture_dir/files/$destination_name"
  fi
}

copy_if_readable /usr/libexec/biometrickitd biometrickitd
copy_if_readable /usr/libexec/remoted remoted
copy_if_readable \
  /System/Library/LaunchDaemons/com.apple.biometrickitd.plist \
  com.apple.biometrickitd.plist
copy_if_readable \
  /System/Library/LaunchDaemons/com.apple.remoted.plist \
  com.apple.remoted.plist
copy_if_readable \
  /System/Library/PrivateFrameworks/BridgeXPC.framework/Versions/A/Resources/Info.plist \
  BridgeXPC-Info.plist
copy_if_readable \
  /System/Library/PrivateFrameworks/BridgeXPC.framework/Versions/A/Resources/version.plist \
  BridgeXPC-version.plist
copy_if_readable \
  /System/Library/PrivateFrameworks/EmbeddedOSSupportHost.framework/Versions/A/Resources/Info.plist \
  EmbeddedOSSupportHost-Info.plist
copy_if_readable \
  /System/Library/PrivateFrameworks/EmbeddedOSSupportHost.framework/Versions/A/Resources/version.plist \
  EmbeddedOSSupportHost-version.plist

if [[ -r /usr/libexec/biometrickitd ]]; then
  file /usr/libexec/biometrickitd >"$capture_dir/biometrickitd-file.txt"
  otool -L /usr/libexec/biometrickitd >"$capture_dir/biometrickitd-libraries.txt"
  codesign -dvvv /usr/libexec/biometrickitd \
    >"$capture_dir/biometrickitd-codesign.txt" 2>&1 || true
  shasum -a 256 /usr/libexec/biometrickitd \
    >"$capture_dir/biometrickitd-sha256.txt"
fi

if [[ -r /usr/libexec/remoted ]]; then
  file /usr/libexec/remoted >"$capture_dir/remoted-file.txt"
  otool -L /usr/libexec/remoted >"$capture_dir/remoted-libraries.txt"
  codesign -dvvv /usr/libexec/remoted \
    >"$capture_dir/remoted-codesign.txt" 2>&1 || true
  shasum -a 256 /usr/libexec/remoted >"$capture_dir/remoted-sha256.txt"
fi

find "$capture_dir" -type f ! -name capture-sha256.txt \
  -exec shasum -a 256 {} + \
  >"$capture_dir/capture-sha256.txt"

echo "Captured read-only bridge artifacts in $capture_dir"
