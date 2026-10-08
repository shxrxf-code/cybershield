import 'dart:io';
import 'dart:typed_data';

import 'package:path_provider/path_provider.dart';

/// Saves downloaded bytes to a sensible user-visible location.
///
/// Prefers the platform downloads directory and falls back to the application
/// documents directory. Returns the absolute path, or throws with a
/// human-readable message when saving is not possible on this platform.
Future<String> saveBytesToDisk(Uint8List bytes, String filename) async {
  final safeName = _sanitizeFilename(filename);
  Directory? dir;
  try {
    dir = await getDownloadsDirectory();
  } catch (_) {
    // Some platforms do not implement getDownloadsDirectory.
  }
  if (dir == null) {
    try {
      dir = await getApplicationDocumentsDirectory();
    } catch (_) {
      // Last resort: current directory.
      dir = Directory.current;
    }
  }
  if (!await dir.exists()) {
    await dir.create(recursive: true);
  }
  final file = File('${dir.path}${Platform.pathSeparator}$safeName');
  await file.writeAsBytes(bytes, flush: true);
  return file.path;
}

/// Sanitises a filename so it cannot influence paths or routing.
String _sanitizeFilename(String name) {
  var cleaned = name.trim();
  cleaned = cleaned.replaceAll(RegExp(r'[\\/:*?"<>|\u0000-\u001F]'), '_');
  cleaned = cleaned.replaceAll(RegExp(r'\.{2,}'), '.');
  if (cleaned.isEmpty || cleaned.startsWith('.')) {
    cleaned = 'quarantined-file.bin';
  }
  if (cleaned.length > 200) {
    cleaned = cleaned.substring(cleaned.length - 200);
  }
  return cleaned;
}