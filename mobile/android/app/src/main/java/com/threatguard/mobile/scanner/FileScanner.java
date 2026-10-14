package com.threatguard.mobile.scanner;

import android.webkit.MimeTypeMap;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

/**
 * The local file-inspection engine.
 *
 * <p>Given a file that the user explicitly handed to the app (through the
 * Storage Access Framework) it:
 *
 * <ol>
 *   <li>validates the size against a configurable limit;
 *   <li>resolves the MIME type from the provider and the file extension;
 *   <li>computes the streaming SHA-256 fingerprint;
 *   <li>runs the {@link SignatureScanner} over the contents; and
 *   <li>returns a structured {@link Inspection} with a {@link ScanResult}.
 * </ol>
 *
 * <p>Everything happens on-device. Nothing here reads another app's private
 * storage or uploads the file anywhere.
 */
public final class FileScanner {

  public static final long DEFAULT_MAX_FILE_SIZE = 100L * 1024 * 1024;         // 100 MiB
  public static final long DEFAULT_MAX_CONTENT_SCAN_BYTES = 32L * 1024 * 1024; // 32 MiB

  /** How aggressively to inspect a file. */
  public static final class Options {
    public long maxFileSize = DEFAULT_MAX_FILE_SIZE;
    public long maxContentScanBytes = DEFAULT_MAX_CONTENT_SCAN_BYTES;
    public boolean computeHash = true;
    public boolean deepScan = true;
  }

  /** Everything the bridge and the UI need to know about one inspected file. */
  public static final class Inspection {
    public String fileName;
    public long fileSize;
    public String extension;
    public String mimeType;
    public String magicType;
    public boolean truncated;
    public String sha256;
    public long durationMs;
    public ScanResult scanResult;
  }

  /** Reports coarse phase progress during a scan. */
  public interface ProgressCallback {
    void onProgress(String phase, int percent);
  }

  private FileScanner() {
  }

  public static Inspection inspect(
      File file,
      String declaredMimeType,
      Options options,
      ProgressCallback progress,
      HashScanner.CancellationSignal signal)
      throws IOException, NoSuchAlgorithmException {

    long started = System.currentTimeMillis();
    Options effective = options == null ? new Options() : options;

    Inspection result = new Inspection();
    result.fileName = file.getName();
    result.fileSize = file.length();
    result.extension = extensionOf(result.fileName);
    result.mimeType = resolveMimeType(declaredMimeType, result.extension);
    result.scanResult = new ScanResult();

    if (signal != null && signal.isCancelled()) {
      throw new ScanCancelledException();
    }

    if (result.fileSize == 0) {
      result.scanResult.add(
          "EMPTY_FILE", "The file is empty (0 bytes).", ScanResult.SEVERITY_INFO);
      if (effective.computeHash) {
        result.sha256 = HashScanner.sha256(file, null, signal);
      }
      result.durationMs = System.currentTimeMillis() - started;
      return result;
    }

    if (result.fileSize > effective.maxFileSize) {
      result.scanResult.setError(
          "E_FILE_TOO_LARGE",
          "File is larger than the " + (effective.maxFileSize / (1024 * 1024)) + " MB scan limit.");
      result.durationMs = System.currentTimeMillis() - started;
      return result;
    }

    result.magicType = SignatureScanner.detectMagic(file);
    step(progress, "inspect", 5);

    if (effective.deepScan) {
      SignatureScanner.checkConsistency(result, result.scanResult);
    }

    if (effective.computeHash) {
      final int from = 5;
      final int to = 75;
      result.sha256 = HashScanner.sha256(
          file,
          (read, total) -> {
            if (progress != null && total > 0) {
              progress.onProgress("hashing", from + (int) ((to - from) * read / total));
            }
          },
          signal);
      step(progress, "hashing", 75);
    }

    if (effective.deepScan) {
      result.truncated = SignatureScanner.scanContent(
          file, result, result.scanResult, effective.maxContentScanBytes, progress, signal);
      SignatureScanner.checkStructure(file, result, result.scanResult);
      step(progress, "signatures", 98);
    }

    result.durationMs = System.currentTimeMillis() - started;
    return result;
  }

  /** Extension without the leading dot, lower-cased. Empty when there is none. */
  static String extensionOf(String fileName) {
    if (fileName == null) {
      return "";
    }
    int dot = fileName.lastIndexOf('.');
    if (dot < 0 || dot == fileName.length() - 1) {
      return "";
    }
    return fileName.substring(dot + 1).toLowerCase(Locale.US);
  }

  /**
   * Prefer the MIME type reported by the content provider; fall back to the
   * extension. Falling back to {@code application/octet-stream} is fine — the
   * scanner never treats an unknown type as malicious.
   */
  static String resolveMimeType(String declared, String extension) {
    if (declared != null && !declared.isEmpty()
        && !"application/octet-stream".equals(declared)) {
      return declared;
    }
    if (extension != null && !extension.isEmpty()) {
      String guessed = MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension);
      if (guessed != null) {
        return guessed;
      }
    }
    return declared != null && !declared.isEmpty() ? declared : "application/octet-stream";
  }

  private static void step(ProgressCallback progress, String phase, int percent) {
    if (progress != null) {
      progress.onProgress(phase, percent);
    }
  }
}
