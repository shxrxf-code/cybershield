/// Local scan-result cache for incremental scanning.
///
/// Stores, per scanned file, its SHA-256, size, modified timestamp and last
/// verdict. When a file is unchanged (`size` and `mtime` match), the scan is
/// skipped and the cached verdict reused — this is what keeps full scans from
/// re-hashing & re-uploading petabytes of unchanged files, and it keeps the
/// battery and network budgets honest.
///
/// The cache is best-effort: if storage is unavailable the scanner just
/// proceeds without caching.
library;

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:path_provider/path_provider.dart';

/// One cache entry for one file path.
class ScanCacheEntry {
  const ScanCacheEntry({
    required this.path,
    required this.size,
    required this.modifiedMs,
    required this.sha256,
    this.verdict,
    required this.scannedAtMs,
  });

  final String path;
  final int size;
  final int modifiedMs;
  final String sha256;
  final String? verdict;
  final int scannedAtMs;

  factory ScanCacheEntry.fromJson(Map<String, dynamic> json) => ScanCacheEntry(
        path: json['path'] as String? ?? '',
        size: json['size'] as int? ?? 0,
        modifiedMs: json['modified_ms'] as int? ?? 0,
        sha256: json['sha256'] as String? ?? '',
        verdict: json['verdict'] as String?,
        scannedAtMs: json['scanned_at_ms'] as int? ?? 0,
      );

  Map<String, dynamic> toJson() => {
        'path': path,
        'size': size,
        'modified_ms': modifiedMs,
        'sha256': sha256,
        'verdict': verdict,
        'scanned_at_ms': scannedAtMs,
      };
}

class ScanCache {
  ScanCache({String? baseDir}) : _baseDir = baseDir;

  static const int _maxEntries = 4000;

  final String? _baseDir;
  Map<String, ScanCacheEntry>? _entries;

  bool get isLoaded => _entries != null;

  Future<File> _file() async {
    final dir = _baseDir ?? await getApplicationSupportDirectory();
    return File('${dir.path}/scan_cache.json');
  }

  Future<Map<String, ScanCacheEntry>> _load() async {
    if (_entries != null) return _entries!;
    try {
      final file = await _file();
      if (!await file.exists()) {
        _entries = <String, ScanCacheEntry>{};
        return _entries!;
      }
      final raw = await file.readAsString();
      final decoded = jsonDecode(raw);
      if (decoded is Map) {
        _entries = <String, ScanCacheEntry>{};
        for (final entry in decoded.values) {
          if (entry is Map) {
            final e = ScanCacheEntry.fromJson(Map<String, dynamic>.from(entry));
            if (e.path.isNotEmpty) _entries![e.path] = e;
          }
        }
      } else {
        _entries = <String, ScanCacheEntry>{};
      }
    } catch (_) {
      _entries = <String, ScanCacheEntry>{};
    }
    return _entries!;
  }

  /// Returns the cached entry when the file is unchanged by size + mtime.
  Future<ScanCacheEntry?> lookup(String path, int size, int modifiedMs) async {
    final entries = await _load();
    final entry = entries[path];
    if (entry == null) return null;
    if (entry.size != size || entry.modifiedMs != modifiedMs) return null;
    return entry;
  }

  Future<void> store(ScanCacheEntry entry) async {
    try {
      final entries = await _load();
      entries[entry.path] = entry;
      // Bound memory + disk.
      if (entries.length > _maxEntries) {
        final sorted = entries.values.toList()
          ..sort((a, b) => b.scannedAtMs.compareTo(a.scannedAtMs));
        entries
          ..clear()
          ..addEntries(sorted.take(_maxEntries).map((e) => MapEntry(e.path, e)));
      }
      final file = await _file();
      await file.writeAsString(
        jsonEncode(entries.map((k, v) => MapEntry(k, v.toJson()))),
        flush: true,
      );
    } catch (_) {
      // Cache is best-effort; scanning continues without it.
    }
  }

  /// Removes an entry (e.g. when a file disappeared).
  Future<void> remove(String path) async {
    try {
      final entries = await _load();
      entries.remove(path);
      final file = await _file();
      await file.writeAsString(
        jsonEncode(entries.map((k, v) => MapEntry(k, v.toJson()))),
        flush: true,
      );
    } catch (_) {
      // ignore
    }
  }
}

/// SHA-256 of a file, streamed in bounded 1 MiB chunks so huge files never
/// load fully into memory (respects the 100 MiB upload ceiling).
Future<String> sha256OfFile(File file) async {
  final digest = AccumulatorSink<Digest>();
  final input = sha256.startChunkedConversion(digest);
  final raf = await file.open();
  try {
    while (true) {
      final chunk = await raf.read(1024 * 1024);
      if (chunk.isEmpty) break;
      input.add(chunk);
    }
  } finally {
    await raf.close();
    input.close();
  }
  return digest.events.single.toString();
}