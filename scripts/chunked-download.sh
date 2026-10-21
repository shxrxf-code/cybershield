#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Chunked, resumable downloader for unstable networks.
#
# WHY
#   On this machine a single long HTTPS read stalls without ever failing, and
#   curl's own "--retry" combined with "-C -" restarts the output file from
#   zero instead of resuming it (observed: a 633 MiB NDK download that had
#   reached 573 MiB dropped back to 65 MiB).
#
#   Downloading in fixed-size byte ranges removes the ambiguity: we always
#   know exactly which offset is missing, so a stalled chunk is simply
#   re-fetched with an explicit Range header.
#
# HOW THE OUTPUT IS WRITTEN
#   The destination file is pre-allocated to the exact expected size and each
#   chunk is written at its absolute offset with dd(conv=notrunc). Writing the
#   same range twice is therefore idempotent, so retries can never corrupt the
#   file — an earlier version that appended to a partial file could double
#   count a range and produce a file that was larger than expected.
#
#   "Accept-Encoding: identity" is requested so that the byte offsets of the
#   HTTP range and of the file on disk are the same; with a compressed
#   response the two would not correspond.
#
# USAGE
#   chunked-download.sh <url> <output-file> <expected-size> [chunk-mib] [parallel]
#
# The expected size is verified at the end, so a truncated file is never
# mistaken for a complete one.
# ---------------------------------------------------------------------------
set -uo pipefail

URL="$1"
OUT="$2"
SIZE="$3"
CHUNK_MIB="${4:-4}"
PARALLEL="${5:-3}"

[ -n "$URL" ] && [ -n "$OUT" ] && [ -n "$SIZE" ] || {
  echo "usage: $0 <url> <output-file> <expected-size> [chunk-mib] [parallel]" >&2
  exit 2
}

CHUNK=$((CHUNK_MIB * 1024 * 1024))
WORK="${OUT}.chunks"
mkdir -p "$WORK"

# Resolve to the final URL first: curl drops the Range header while following
# a redirect, which would silently turn a ranged request into a full download.
# The resolution uses a one-byte range request — a plain GET would stream the
# whole file to /dev/null before returning, which takes as long as the
# download itself.
RESOLVED="$(curl -sS -L -r 0-0 -o /dev/null --connect-timeout 30 --max-time 60 \
            -w '%{url_effective}' "$URL" 2>/dev/null)"
[ -n "$RESOLVED" ] || RESOLVED="$URL"

# Pre-allocate the destination so chunks can be written at absolute offsets.
truncate -s "$SIZE" "$OUT"

# commit_chunk <part-file> <byte-offset>
# Writes the part file into $OUT at the given absolute byte offset.
commit_chunk() {
  local src="$1" offset="$2"
  if dd if="$src" of="$OUT" bs=1M seek="$offset" oflag=seek_bytes conv=notrunc status=none 2>/dev/null; then
    return 0
  fi
  # Fall back for a coreutils without oflag=seek_bytes.
  dd if="$src" of="$OUT" bs=1 seek="$offset" conv=notrunc status=none
}

# fetch_chunk <index>
# Downloads the byte range for chunk <index> straight into $OUT at its
# absolute offset. Retries are safe: writing the same range again is a no-op.
fetch_chunk() {
  local idx="$1"
  local start=$((idx * CHUNK))
  local end=$((start + CHUNK - 1))
  [ "$end" -ge "$SIZE" ] && end=$((SIZE - 1))
  local want=$((end - start + 1))
  local part="$WORK/$idx.part"
  local fetch="$WORK/$idx.fetch"
  local marker="$WORK/$idx.done"
  local attempt=0

  # A completed chunk is recorded with a marker, so an interrupted run can be
  # restarted without re-fetching the chunks that already landed in $OUT.
  [ -f "$marker" ] && return 0

  # $part always holds this chunk's bytes starting at $start, so its size is
  # exactly the offset of the next byte still missing.
  #
  # The chunk is committed into $OUT with dd's oflag=seek_bytes, which
  # interprets the seek as a byte offset. Plain "bs=1 seek=N" would copy the
  # chunk byte by byte (4 million syscalls per chunk); with a large block
  # size and seek_bytes the same write is a handful of calls.
  while [ "$attempt" -lt 40 ]; do
    attempt=$((attempt + 1))

    local have=0
    [ -f "$part" ] && have="$(stat -c %s "$part" 2>/dev/null || echo 0)"

    if [ "$have" -ge "$want" ]; then
      # The chunk is already complete (a previous run was interrupted between
      # downloading and committing it). Commit it instead of re-downloading.
      truncate -s "$want" "$part"
      commit_chunk "$part" "$start"
      rm -f "$part"
      : > "$marker"
      return 0
    fi

    local from=$((start + have))
    rm -f "$fetch"
    if curl -sS -L --connect-timeout 30 --speed-time 45 --speed-limit 1024 \
         -H 'Accept-Encoding: identity' \
         -r "${from}-${end}" -o "$fetch" "$RESOLVED" 2>"$WORK/.$idx.err"; then
      local got
      got="$(stat -c %s "$fetch" 2>/dev/null || echo 0)"
      if [ "$got" -gt "$want" ]; then
        # The server ignored the range and sent more than requested; keep the
        # first $want bytes, which are the ones that were asked for.
        truncate -s "$want" "$fetch"
        got="$want"
      fi
      # Append to the partial chunk instead of replacing it, so progress
      # survives a short read.
      cat "$fetch" >> "$part" 2>/dev/null
      rm -f "$fetch"
      have="$(stat -c %s "$part" 2>/dev/null || echo 0)"

      if [ "$have" -eq "$want" ]; then
        commit_chunk "$part" "$start"
        rm -f "$part"
        : > "$marker"
        return 0
      fi
      printf 'chunk %s attempt %s: got %s of %s bytes (range %s-%s)\n' \
        "$idx" "$attempt" "$have" "$want" "$from" "$end" >> "$WORK/errors.log"
    else
      # Record why the transfer failed; the error is what makes a stuck chunk
      # diagnosable instead of just "FAILED".
      printf 'chunk %s attempt %s: %s\n' "$idx" "$attempt" \
        "$(tr '\n' ' ' < "$WORK/.$idx.err" 2>/dev/null)" >> "$WORK/errors.log"
    fi
  done

  echo "chunk $idx FAILED (offset $start)" >&2
  return 1
}

TOTAL_CHUNKS=$(( (SIZE + CHUNK - 1) / CHUNK ))
echo "downloading $SIZE bytes in $TOTAL_CHUNKS chunks of ${CHUNK_MIB} MiB (parallel=$PARALLEL)"

run_pool() {
  local idx=0
  local failed=0
  while [ "$idx" -lt "$TOTAL_CHUNKS" ]; do
    local pids=()
    local n=0
    while [ "$n" -lt "$PARALLEL" ] && [ "$idx" -lt "$TOTAL_CHUNKS" ]; do
      fetch_chunk "$idx" &
      pids+=($!)
      idx=$((idx + 1))
      n=$((n + 1))
    done
    for p in "${pids[@]}"; do
      wait "$p" || failed=1
    done
  done
  return $failed
}

if ! run_pool; then
  echo "ERROR: one or more chunks failed" >&2
  exit 1
fi

FINAL="$(stat -c %s "$OUT")"
if [ "$FINAL" -ne "$SIZE" ]; then
  echo "ERROR: assembled $FINAL bytes, expected $SIZE" >&2
  exit 1
fi

rm -rf "$WORK"
echo "OK $OUT ($FINAL bytes)"
