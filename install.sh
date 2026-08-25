#!/bin/sh
# skret one-shot installer.
# Usage:
#   curl -fsSL https://skret.n24q02m.com/install.sh | sh
#   curl -fsSL https://skret.n24q02m.com/install.sh | sh -s -- --version=v1.0.0 --user
# Flags:
#   --version=<tag>   install a specific release tag (default: latest)
#   --prefix=<path>   install target dir (default: /usr/local/bin or ~/.local/bin)
#   --user            force user-mode install to ~/.local/bin (no sudo)
#   --no-completion   skip shell completion install
#   --quiet           suppress progress output
# Env:
#   SKRET_INSECURE_SKIP_VERIFY=1  install only with an explicit signature-verification bypass

set -eu

REPO="n24q02m/skret"
VERSION=""
PREFIX=""
USER_INSTALL=0
NO_COMPLETION=0
QUIET=0

while [ $# -gt 0 ]; do
  case "$1" in
    --version=*) VERSION="${1#*=}"; shift ;;
    --prefix=*) PREFIX="${1#*=}"; shift ;;
    --user) USER_INSTALL=1; shift ;;
    --no-completion) NO_COMPLETION=1; shift ;;
    --quiet) QUIET=1; shift ;;
    -h|--help)
      sed -n '2,14p' "$0"
      exit 0
      ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

log() { [ "$QUIET" = 1 ] || echo "==> $*"; }
err() { echo "skret install: $*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || err "missing required tool: $1"; }
need curl
need tar
need uname
need awk
need sed

need tr
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux|darwin) ;;
  *) err "unsupported OS: $os (use install.ps1 on Windows)" ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) err "unsupported arch: $arch" ;;
esac

if [ -z "$VERSION" ]; then
  log "Detecting latest release"
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
fi
[ -n "$VERSION" ] || err "could not detect latest version"

# Strip leading 'v' for asset name templating (releases use skret_1.0.0_... not skret_v1.0.0_...)
ver_trim="${VERSION#v}"

if [ -z "$PREFIX" ]; then
  if [ "$USER_INSTALL" = 1 ]; then
    PREFIX="$HOME/.local/bin"
  elif [ -w "/usr/local/bin" ]; then
    PREFIX="/usr/local/bin"
  elif command -v sudo >/dev/null 2>&1 && [ -d "/usr/local/bin" ]; then
    PREFIX="/usr/local/bin"
    USE_SUDO=1
  else
    PREFIX="$HOME/.local/bin"
  fi
fi

# Darwin -> darwin, Linux -> linux (lowercase matches release archives)
asset="skret_${ver_trim}_${os}_${arch}.tar.gz"
url="https://github.com/$REPO/releases/download/$VERSION/$asset"
checksum_url="https://github.com/$REPO/releases/download/$VERSION/checksums.txt"
# goreleaser signs with `--bundle`, so the release carries one signature artifact
# (checksums.txt.bundle). It does not publish separate .pem/.sig files.
bundle_url="https://github.com/$REPO/releases/download/$VERSION/checksums.txt.bundle"

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t 'skret-install')
chmod 0700 "$tmp" 2>/dev/null || { rm -rf "$tmp" 2>/dev/null || true; err "could not secure temporary directory"; }

dest=""
dest_tmp=""
dest_bak=""
had_prior=0
prior_stashed=0
new_installed=0
install_ok=0

run_privileged() {
  if [ -n "${USE_SUDO:-}" ]; then
    sudo "$@"
  else
    "$@"
  fi
}

path_exists() {
  [ -e "$1" ] || [ -L "$1" ]
}

rollback_and_cleanup() {
  if [ "$install_ok" -ne 1 ]; then
    # A failed swap can leave the new target in place after the old target has
    # already been moved aside. Remove only that known new target, then restore
    # the byte-identical backup. Before the backup move, an existing prior
    # target is deliberately left alone.
    if [ "$prior_stashed" -eq 1 ]; then
      if [ -n "$dest" ] && path_exists "$dest"; then
        run_privileged rm -f -- "$dest" 2>/dev/null || true
      fi
      if [ -n "$dest_bak" ] && path_exists "$dest_bak"; then
        run_privileged mv -f -- "$dest_bak" "$dest" 2>/dev/null || true
      fi
    elif [ "$had_prior" -eq 0 ] && [ "$new_installed" -eq 1 ] && [ -n "$dest" ] && path_exists "$dest"; then
      run_privileged rm -f -- "$dest" 2>/dev/null || true
    fi

    if [ -n "$dest_tmp" ] && path_exists "$dest_tmp"; then
      run_privileged rm -f -- "$dest_tmp" 2>/dev/null || true
    fi
  elif [ -n "$dest_bak" ] && path_exists "$dest_bak"; then
    # The backup is normally removed before install_ok is set. Keep this as a
    # final success-path cleanup for shells that report an unusual move result.
    run_privileged rm -f -- "$dest_bak" 2>/dev/null || true
  fi

  if [ -n "$tmp" ] && [ -d "$tmp" ]; then
    rm -rf "$tmp" 2>/dev/null || true
  fi
}
trap rollback_and_cleanup EXIT INT TERM

log "Downloading $asset"
curl -fsSL "$url" -o "$tmp/skret.tar.gz"
curl -fsSL "$checksum_url" -o "$tmp/checksums.txt"

log "Verifying SHA256 checksum"
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/skret.tar.gz" | awk '{print $1}')
else
  actual=$(shasum -a 256 "$tmp/skret.tar.gz" | awk '{print $1}')
fi

# Every non-empty checksum row must be a complete SHA-256 row. In particular,
# never accept the first matching row when a release has a duplicate filename.
checksum_result=$(LC_ALL=C awk -v asset="$asset" '
  BEGIN { bad = 0; matches = 0; expected = "" }
  {
    if ($0 ~ /^[[:space:]]*$/) next
    if (NF != 2 || length($1) != 64 || $1 !~ /^[0-9A-Fa-f]+$/ || $2 !~ /^[^[:space:]]+$/) {
      bad = 1
      next
    }
    if ($2 == asset) {
      matches++
      expected = $1
    }
  }
  END {
    if (bad) {
      print "ERR: malformed checksum row"
    } else if (matches == 0) {
      print "ERR: no checksum row for " asset
    } else if (matches != 1) {
      print "ERR: duplicate checksum rows for " asset
    } else {
      print "OK:" expected
    }
  }
' "$tmp/checksums.txt")
case "$checksum_result" in
  OK:*) expected=${checksum_result#OK:} ;;
  ERR:*) err "$checksum_result" ;;
  *) err "invalid checksum parser result" ;;
esac
expected=$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')
[ "$expected" = "$actual" ] || err "checksum mismatch (expected $expected, got $actual)"

if [ "${SKRET_INSECURE_SKIP_VERIFY:-}" = "1" ]; then
  log "WARN: skipping cosign signature verification because SKRET_INSECURE_SKIP_VERIFY=1"
else
  command -v cosign >/dev/null 2>&1 || err "missing required signature verification tool: cosign (set SKRET_INSECURE_SKIP_VERIFY=1 only to bypass verification)"
  log "Verifying cosign Sigstore signature"
  curl -fsSL "$bundle_url" -o "$tmp/checksums.txt.bundle"
  [ -s "$tmp/checksums.txt.bundle" ] || err "missing or empty signature bundle for $VERSION"
  if ! cosign verify-blob \
      --bundle "$tmp/checksums.txt.bundle" \
      --certificate-identity-regexp "https://github.com/$REPO/.+" \
      --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
      "$tmp/checksums.txt" >/dev/null; then
    err "signature verification failed for $VERSION. The download does not carry a valid Sigstore signature from $REPO. Set SKRET_INSECURE_SKIP_VERIFY=1 to install anyway."
  fi
fi

# SAFE-ARCHIVE-V1 Policy Constants
MAX_ENTRIES=16
MAX_TOTAL_BYTES=104857600  # 100 MiB
MAX_ENTRY_BYTES=104857600  # 100 MiB
MAX_RATIO=20
ALLOWLIST="skret LICENSE LICENSE.txt LICENSE.md README README.md README.txt CHANGELOG CHANGELOG.md CHANGELOG.txt"

validate_safe_archive_v1() {
  archive_path="$1"
  archive_size=$(wc -c < "$archive_path" 2>/dev/null | awk '{print $1}')
  [ -n "$archive_size" ] && [ "$archive_size" -gt 0 ] || err "SAFE-ARCHIVE-V1: empty or missing archive file"

  # Force the stable C locale so tar's long listing uses machine-readable
  # GNU/BSD date tokens. The validator then takes the size immediately before
  # that token; it must not guess from another numeric field.
  listing=$(LC_ALL=C tar -ztvf "$archive_path" 2>/dev/null) || err "SAFE-ARCHIVE-V1: malformed tar.gz archive"
  [ -n "$listing" ] || err "SAFE-ARCHIVE-V1: archive has no entries"

  validation_result=$(printf '%s\n' "$listing" | LC_ALL=C awk -v max_entries="$MAX_ENTRIES" \
                                                     -v max_total="$MAX_TOTAL_BYTES" \
                                                     -v max_entry="$MAX_ENTRY_BYTES" \
                                                     -v max_ratio="$MAX_RATIO" \
                                                     -v arch_size="$archive_size" \
                                                     -v allowlist="$ALLOWLIST" '
    function is_time(s) {
      return s ~ /^[0-9][0-9]:[0-9][0-9](:[0-9][0-9])?$/
    }
    function is_gnu_date(s) {
      return s ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/
    }
    function is_month(s) {
      return s ~ /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$/
    }
    BEGIN {
      split(allowlist, arr, " ")
      for (i in arr) allowed[arr[i]] = 1
      entry_count = 0
      total_size = 0
      has_binary = 0
    }
    {
      if ($0 ~ /^[[:space:]]*$/) next
      entry_count++
      if (entry_count > max_entries) {
        print "ERR: entry count exceeds maximum " max_entries
        exit
      }

      perm = $1
      if (substr(perm, 1, 1) != "-") {
        print "ERR: non-regular file entry: " $0
        exit
      }

      # GNU tar: ... SIZE YYYY-MM-DD HH:MM NAME
      # BSD tar:  ... SIZE Mon DD HH:MM[|YYYY] NAME
      # In both formats SIZE is the field immediately before the date token.
      date_start = 0
      date_end = 0
      for (i = 2; i <= NF; i++) {
        if (i + 1 <= NF && is_gnu_date($i) && is_time($(i + 1))) {
          date_start = i
          date_end = i + 1
          break
        }
        if (i + 2 <= NF && is_month($i) && $(i + 1) ~ /^[0-9][0-9]?$/ && (is_time($(i + 2)) || $(i + 2) ~ /^[0-9][0-9][0-9][0-9]$/)) {
          date_start = i
          date_end = i + 2
          break
        }
      }
      if (!date_start || date_start <= 1 || $(date_start - 1) !~ /^[0-9]+$/) {
        print "ERR: could not identify a portable entry size before date token: " $0
        exit
      }
      entry_size = $(date_start - 1) + 0
      if (date_end + 1 != NF) {
        print "ERR: entry name is not a single root-level field: " $0
        exit
      }
      name = $(date_end + 1)
      if (name ~ /^\.\//) name = substr(name, 3)

      # Only a single allowlisted basename may appear at archive root.
      if (name ~ /\// || name ~ /\\/ || name ~ /:/ || name ~ /\.\./ || name == ".") {
        print "ERR: illegal path or traversal in entry name: " name
        exit
      }
      if (name !~ /^[A-Za-z0-9._-]+$/) {
        print "ERR: unsafe characters in entry name: " name
        exit
      }
      if (!allowed[name]) {
        print "ERR: unexpected file in release archive: " name
        exit
      }

      lower = tolower(name)
      if (seen[lower]) {
        print "ERR: duplicate or case-colliding entry name: " name
        exit
      }
      seen[lower] = 1

      if (entry_size > max_entry) {
        print "ERR: entry size exceeds maximum: " name " (" entry_size " > " max_entry ")"
        exit
      }
      total_size += entry_size
      if (name == "skret") has_binary++
    }
    END {
      if (entry_count == 0) {
        print "ERR: archive contains no entries"
      } else if (has_binary != 1) {
        print "ERR: archive must contain exactly one skret binary, found " has_binary
      } else if (total_size > max_total) {
        print "ERR: total uncompressed size exceeds maximum (" total_size " > " max_total ")"
      } else if (arch_size <= 0 || (total_size / arch_size) > max_ratio) {
        if (arch_size <= 0) print "ERR: archive size is unavailable for compression-ratio validation"
        else print "ERR: compression ratio bomb detected (" total_size "/" arch_size " > " max_ratio ")"
      } else {
        print "OK"
      }
    }
  ')

  case "$validation_result" in
    OK*) ;;
    ERR:*) err "SAFE-ARCHIVE-V1 validation failed: ${validation_result#ERR: }" ;;
    *) err "SAFE-ARCHIVE-V1 validation failed: $validation_result" ;;
  esac
}

check_destination_prefix() {
  check_path="$1"
  case "$check_path" in
    /*) current="/"; remainder=${check_path#/} ;;
    *) current=$(pwd -P); remainder="$check_path" ;;
  esac

  while [ -n "$remainder" ]; do
    case "$remainder" in
      */*) component=${remainder%%/*}; remainder=${remainder#*/} ;;
      *) component="$remainder"; remainder="" ;;
    esac
    [ -n "$component" ] || continue
    [ "$component" = "." ] && continue
    [ "$component" = ".." ] && err "destination prefix contains parent traversal: $check_path"

    if [ "$current" = "/" ]; then candidate="/$component"; else candidate="$current/$component"; fi
    if [ -L "$candidate" ]; then
      err "destination prefix contains a symlinked ancestor: $candidate"
    fi
    if [ -e "$candidate" ] || [ -d "$candidate" ]; then
      [ -d "$candidate" ] || err "destination prefix component is not a directory: $candidate"
    fi
    current="$candidate"
  done
}

log "Validating release archive (SAFE-ARCHIVE-V1)"
validate_safe_archive_v1 "$tmp/skret.tar.gz"

stage_dir="$tmp/stage"
mkdir -m 0700 "$stage_dir" 2>/dev/null || mkdir -p "$stage_dir" || err "could not create secure staging directory"
chmod 0700 "$stage_dir" 2>/dev/null || err "could not secure staging directory"

log "Extracting to staging"
tar -xzf "$tmp/skret.tar.gz" -C "$stage_dir"

# Validate the complete extracted tree, including dotfiles, before touching the
# destination. Every extracted root entry must be a regular allowlisted file.
for file_path in "$stage_dir"/* "$stage_dir"/.[!.]* "$stage_dir"/..?*; do
  [ -e "$file_path" ] || [ -L "$file_path" ] || continue
  [ -f "$file_path" ] && [ ! -L "$file_path" ] || err "SAFE-ARCHIVE-V1: extracted entry is not a regular file: $(basename "$file_path")"
  base_name=$(basename "$file_path")
  case " $ALLOWLIST " in
    *" $base_name "*) ;;
    *) err "SAFE-ARCHIVE-V1: staging directory contains unexpected extracted file: $base_name" ;;
  esac
done

extracted_bin="$stage_dir/skret"
[ -f "$extracted_bin" ] && [ ! -L "$extracted_bin" ] || err "SAFE-ARCHIVE-V1: extracted binary missing or is a symlink"
chmod 0755 "$extracted_bin"

# Check every existing destination-prefix ancestor before mkdir -p or swap.
# Re-check after mkdir in case the final component was just created.
check_destination_prefix "$PREFIX"
if [ ! -d "$PREFIX" ]; then
  run_privileged mkdir -p -- "$PREFIX"
fi
check_destination_prefix "$PREFIX"
[ -d "$PREFIX" ] && [ ! -L "$PREFIX" ] || err "destination prefix is not a valid directory: $PREFIX"

dest="$PREFIX/skret"
# Reject an existing target unless it is a regular, non-symlink file.
if [ -e "$dest" ] || [ -L "$dest" ]; then
  [ -f "$dest" ] && [ ! -L "$dest" ] || err "destination target is not a regular file: $dest"
  had_prior=1
else
  had_prior=0
fi
dest_tmp="$PREFIX/.skret.tmp.$$"
dest_bak="$PREFIX/.skret.bak.$$"

log "Installing $dest (atomic swap)"
if [ "$had_prior" -eq 1 ]; then
  run_privileged cp -p -- "$extracted_bin" "$dest_tmp" || err "failed to copy binary into staging"
  run_privileged chmod 0755 "$dest_tmp" || err "failed to set staged binary permissions"
  if ! run_privileged mv -f -- "$dest" "$dest_bak"; then
    if path_exists "$dest_bak" && ! path_exists "$dest"; then prior_stashed=1; fi
    err "failed to move prior binary aside"
  fi
  prior_stashed=1
else
  run_privileged cp -p -- "$extracted_bin" "$dest_tmp" || err "failed to copy binary into staging"
  run_privileged chmod 0755 "$dest_tmp" || err "failed to set staged binary permissions"
fi

if ! run_privileged mv -f -- "$dest_tmp" "$dest"; then
  if path_exists "$dest" && [ "$had_prior" -eq 0 ]; then new_installed=1; fi
  err "failed to activate staged binary"
fi
new_installed=1

# Verify installed binary runs --version before committing.
log "Verifying installed binary"
if ! version_output=$("$dest" --version 2>&1); then
  err "installed binary verification failed (--version exited non-zero); rolling back"
fi

# Only mark success after the backup has been removed. If this cleanup fails,
# the EXIT trap still knows to restore the prior byte-identical binary.
if [ "$had_prior" -eq 1 ] && path_exists "$dest_bak"; then
  run_privileged rm -f -- "$dest_bak" || err "failed to remove backup after successful smoke test"
fi
install_ok=1

if [ "$NO_COMPLETION" = 0 ]; then
  for shell in bash zsh fish; do
    if command -v "$shell" >/dev/null 2>&1; then
      log "Generating $shell completion (run 'skret completion $shell' to refresh)"
      break
    fi
  done
fi

log "Installed: $version_output"
case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *) log "WARN: $PREFIX is not in PATH. Add: export PATH=\"$PREFIX:\$PATH\"" ;;
esac
