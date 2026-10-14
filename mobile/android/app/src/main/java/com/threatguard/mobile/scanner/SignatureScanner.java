package com.threatguard.mobile.scanner;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Checks a file against known suspicious signatures and structural
 * inconsistencies.
 *
 * <p>Two rules keep the verdict honest:
 *
 * <ul>
 *   <li>A file is only ever reported as a threat when a <em>definitive</em>
 *       signature matched (currently the EICAR anti-malware test string). All
 *       other checks are heuristics and can only raise "suspicious".
 *   <li>An unusual extension or MIME type is never, on its own, treated as
 *       malware. A mismatch between the name and the contents is reported at
 *       "low" severity so the user can decide.
 * </ul>
 */
public final class SignatureScanner {

  // Content families used for magic-byte / extension consistency checks.
  static final String FAMILY_PDF = "pdf";
  static final String FAMILY_ZIP = "zip";   // zip, apk, docx, xlsx, jar, odt ...
  static final String FAMILY_JPEG = "jpeg";
  static final String FAMILY_PNG = "png";
  static final String FAMILY_GIF = "gif";
  static final String FAMILY_WEBP = "webp";
  static final String FAMILY_RAR = "rar";
  static final String FAMILY_7Z = "7z";
  static final String FAMILY_OLE = "ole";   // legacy .doc/.xls/.ppt
  static final String FAMILY_ELF = "elf";
  static final String FAMILY_DEX = "dex";
  static final String FAMILY_TEXT = "text";

  private static final String SEVERITY_HIGH = ScanResult.SEVERITY_HIGH;
  private static final String SEVERITY_MEDIUM = ScanResult.SEVERITY_MEDIUM;
  private static final String SEVERITY_LOW = ScanResult.SEVERITY_LOW;
  private static final String SEVERITY_INFO = ScanResult.SEVERITY_INFO;

  private static final int HEADER_BYTES = 16;
  private static final int STREAM_BUFFER = 64 * 1024;

  /** Human-readable description and severity for every finding code. */
  private static final Map<String, String[]> FINDING_META = new HashMap<>();

  static {
    FINDING_META.put("EICAR_TEST_FILE",
        new String[]{"EICAR anti-malware test signature.", SEVERITY_HIGH});
    FINDING_META.put("PDF_JAVASCRIPT",
        new String[]{"PDF contains embedded JavaScript.", SEVERITY_MEDIUM});
    FINDING_META.put("PDF_EMBEDDED_FILES",
        new String[]{"PDF contains embedded files.", SEVERITY_MEDIUM});
    FINDING_META.put("PDF_LAUNCH_ACTION",
        new String[]{"PDF contains a launch action.", SEVERITY_MEDIUM});
    FINDING_META.put("PDF_OPENACTION",
        new String[]{"PDF runs an action when opened.", SEVERITY_LOW});
    FINDING_META.put("PDF_AUTO_ACTION",
        new String[]{"PDF contains automatic actions.", SEVERITY_LOW});
    FINDING_META.put("EXTENSION_CONTENT_MISMATCH",
        new String[]{"The file's contents do not match its extension.", SEVERITY_LOW});
    FINDING_META.put("APK_MISSING_MANIFEST",
        new String[]{"APK is missing its AndroidManifest.xml.", SEVERITY_MEDIUM});
    FINDING_META.put("APK_MISSING_DEX",
        new String[]{"APK contains no DEX bytecode.", SEVERITY_MEDIUM});
    FINDING_META.put("APK_PATH_TRAVERSAL",
        new String[]{"APK contains an unsafe archive entry name.", SEVERITY_MEDIUM});
    FINDING_META.put("APK_UNREADABLE",
        new String[]{"The APK archive could not be read.", SEVERITY_LOW});
    FINDING_META.put("EMPTY_FILE",
        new String[]{"The file is empty (0 bytes).", SEVERITY_INFO});
    FINDING_META.put("UNRECOGNISED_TYPE",
        new String[]{"Unrecognised file type; checked for known signatures only.", SEVERITY_INFO});
  }

  /** A byte pattern that maps to a finding code. */
  private static final class Pattern {
    final String code;
    final byte[] bytes;

    Pattern(String code, byte[] bytes) {
      this.code = code;
      this.bytes = bytes;
    }
  }

  private static final byte[] EICAR = ascii(
      "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

  private static final List<Pattern> PDF_PATTERNS = new ArrayList<>();

  static {
    PDF_PATTERNS.add(new Pattern("PDF_JAVASCRIPT", ascii("/JavaScript")));
    PDF_PATTERNS.add(new Pattern("PDF_JAVASCRIPT", ascii("/JS")));
    PDF_PATTERNS.add(new Pattern("PDF_EMBEDDED_FILES", ascii("/EmbeddedFile")));
    PDF_PATTERNS.add(new Pattern("PDF_LAUNCH_ACTION", ascii("/Launch")));
    PDF_PATTERNS.add(new Pattern("PDF_OPENACTION", ascii("/OpenAction")));
    PDF_PATTERNS.add(new Pattern("PDF_AUTO_ACTION", ascii("/AA")));
  }

  private SignatureScanner() {
  }

  /**
   * A single pass that searches {@code file} for the supplied patterns. Only the
   * first {@code maxBytes} are inspected; the caller is told when the scan was
   * truncated. Returns the set of finding codes that matched.
   */
  static Set<String> searchPatterns(
      File file, List<Pattern> patterns, long maxBytes, int percentFrom, int percentTo,
      FileScanner.ProgressCallback progress, HashScanner.CancellationSignal signal)
      throws IOException {

    if (patterns.isEmpty()) {
      return new HashSet<>();
    }

    int maxLength = 1;
    for (Pattern p : patterns) {
      maxLength = Math.max(maxLength, p.bytes.length);
    }

    Set<String> found = new HashSet<>();
    byte[] tail = new byte[maxLength - 1];
    int tailLength = 0;
    byte[] buffer = new byte[STREAM_BUFFER];
    long totalRead = 0;

    try (InputStream in = new BufferedInputStream(new FileInputStream(file), STREAM_BUFFER)) {
      int n;
      while ((n = in.read(buffer)) != -1) {
        if (signal != null && signal.isCancelled()) {
          throw new ScanCancelledException();
        }
        byte[] window = new byte[tailLength + n];
        System.arraycopy(tail, 0, window, 0, tailLength);
        System.arraycopy(buffer, 0, window, tailLength, n);

        for (Pattern p : patterns) {
          if (!found.contains(p.code) && indexOf(window, p.bytes) >= 0) {
            found.add(p.code);
          }
        }

        int keep = Math.min(maxLength - 1, window.length);
        System.arraycopy(window, window.length - keep, tail, 0, keep);
        tailLength = keep;

        totalRead += n;
        if (progress != null && percentTo > percentFrom) {
          int pct = percentFrom;
          if (maxBytes > 0) {
            pct = percentFrom + (int) Math.min(percentTo - percentFrom,
                (totalRead * (percentTo - percentFrom)) / maxBytes);
          }
          progress.onProgress("signatures", pct);
        }
        if (maxBytes > 0 && totalRead >= maxBytes) {
          break;
        }
      }
    }
    return found;
  }

  /**
   * Inspects the readable content of a file for signature matches and records
   * the findings. Returns {@code true} when the scan was limited to the first
   * {@code maxBytes} of the file.
   */
  static boolean scanContent(
      File file, FileScanner.Inspection inspection, ScanResult scan, long maxBytes,
      FileScanner.ProgressCallback progress, HashScanner.CancellationSignal signal)
      throws IOException {

    List<Pattern> patterns = new ArrayList<>();
    // The EICAR string is the only definitive (high severity) signature we hold
    // locally; it is what the test suite and the UI use to prove the engine
    // actually processes file bytes.
    patterns.add(new Pattern("EICAR_TEST_FILE", EICAR));

    boolean isPdf = FAMILY_PDF.equals(inspection.magicType)
        || "application/pdf".equals(inspection.mimeType);
    if (isPdf) {
      patterns.addAll(PDF_PATTERNS);
    }

    Set<String> matched = searchPatterns(file, patterns, maxBytes, 75, 95, progress, signal);

    boolean truncated = file.length() > maxBytes;
    if (truncated) {
      scan.markTruncated();
    }

    for (String code : matched) {
      addFinding(scan, code);
    }
    return truncated;
  }

  /**
   * Compares the file's extension and declared MIME type against its actual
   * magic bytes. A mismatch is reported as a low-severity finding; it never
   * escalates the file to a threat on its own.
   */
  static void checkConsistency(FileScanner.Inspection inspection, ScanResult scan) {
    String expected = expectedFamily(inspection.extension);
    String magic = inspection.magicType;

    if (expected != null && magic != null && !expected.equals(magic)) {
      scan.add(
          "EXTENSION_CONTENT_MISMATCH",
          "Contents look like " + magic + " but the file is named ." + inspection.extension + ".",
          SEVERITY_LOW);
    } else if (expected == null && magic == null) {
      addFinding(scan, "UNRECOGNISED_TYPE");
    }
  }

  /**
   * Structural checks that apply to specific container formats. Currently the
   * only one is APK: a package that is not a readable zip, or that lacks a
   * manifest/dex, is reported (at most) as suspicious.
   */
  static void checkStructure(File file, FileScanner.Inspection inspection, ScanResult scan) {
    boolean isApk = "application/vnd.android.package-archive".equals(inspection.mimeType)
        || "apk".equals(inspection.extension);
    if (!isApk) {
      return;
    }

    try (ZipFile zip = new ZipFile(file)) {
      boolean hasManifest = false;
      boolean hasDex = false;
      Enumeration<? extends ZipEntry> entries = zip.entries();
      while (entries.hasMoreElements()) {
        ZipEntry entry = entries.nextElement();
        String name = entry.getName();
        if ("AndroidManifest.xml".equals(name)) {
          hasManifest = true;
        }
        if (name.endsWith(".dex")) {
          hasDex = true;
        }
        if (name.contains("..") || name.startsWith("/")) {
          scan.add("APK_PATH_TRAVERSAL",
              "Archive entry escapes the archive root: " + name, SEVERITY_MEDIUM);
        }
      }
      if (!hasManifest) {
        addFinding(scan, "APK_MISSING_MANIFEST");
      }
      if (!hasDex) {
        addFinding(scan, "APK_MISSING_DEX");
      }
    } catch (Exception e) {
      addFinding(scan, "APK_UNREADABLE");
    }
  }

  private static void addFinding(ScanResult scan, String code) {
    String[] meta = FINDING_META.get(code);
    if (meta == null) {
      scan.add(code, code, SEVERITY_INFO);
    } else {
      scan.add(code, meta[0], meta[1]);
    }
  }

  /** Reads the leading bytes of a file and classifies its container family. */
  static String detectMagic(File file) {
    try (InputStream in = new BufferedInputStream(new FileInputStream(file))) {
      byte[] head = new byte[HEADER_BYTES];
      int n = in.read(head);
      if (n <= 0) {
        return null;
      }
      return detectMagic(head, n);
    } catch (IOException e) {
      return null;
    }
  }

  static String detectMagic(byte[] b, int n) {
    if (n >= 5 && b[0] == '%' && b[1] == 'P' && b[2] == 'D' && b[3] == 'F' && b[4] == '-') {
      return FAMILY_PDF;
    }
    if (n >= 4 && b[0] == 'P' && b[1] == 'K'
        && (b[2] == 3 || b[2] == 5 || b[2] == 7) && (b[3] == 4 || b[3] == 6 || b[3] == 8)) {
      return FAMILY_ZIP;
    }
    if (n >= 3 && u(b[0]) == 0xFF && u(b[1]) == 0xD8 && u(b[2]) == 0xFF) {
      return FAMILY_JPEG;
    }
    if (n >= 8 && u(b[0]) == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G'
        && u(b[4]) == 0x0D && u(b[5]) == 0x0A && u(b[6]) == 0x1A && u(b[7]) == 0x0A) {
      return FAMILY_PNG;
    }
    if (n >= 6 && b[0] == 'G' && b[1] == 'I' && b[2] == 'F' && b[3] == '8'
        && (b[4] == '7' || b[4] == '9') && b[5] == 'a') {
      return FAMILY_GIF;
    }
    if (n >= 12 && b[0] == 'R' && b[1] == 'I' && b[2] == 'F' && b[3] == 'F'
        && b[8] == 'W' && b[9] == 'E' && b[10] == 'B' && b[11] == 'P') {
      return FAMILY_WEBP;
    }
    if (n >= 7 && b[0] == 'R' && b[1] == 'a' && b[2] == 'r' && b[3] == '!'
        && u(b[4]) == 0x1A && u(b[5]) == 0x07) {
      return FAMILY_RAR;
    }
    if (n >= 6 && u(b[0]) == 0x37 && u(b[1]) == 0x7A && u(b[2]) == 0xBC && u(b[3]) == 0xAF
        && u(b[4]) == 0x27 && u(b[5]) == 0x1C) {
      return FAMILY_7Z;
    }
    if (n >= 8 && u(b[0]) == 0xD0 && u(b[1]) == 0xCF && u(b[2]) == 0x11 && u(b[3]) == 0xE0
        && u(b[4]) == 0xA1 && u(b[5]) == 0xB1 && u(b[6]) == 0x1A && u(b[7]) == 0xE1) {
      return FAMILY_OLE;
    }
    if (n >= 4 && u(b[0]) == 0x7F && b[1] == 'E' && b[2] == 'L' && b[3] == 'F') {
      return FAMILY_ELF;
    }
    if (n >= 4 && b[0] == 'd' && b[1] == 'e' && b[2] == 'x' && b[3] == '\n') {
      return FAMILY_DEX;
    }
    if (isProbablyText(b, n)) {
      return FAMILY_TEXT;
    }
    return null;
  }

  /** The container family a file's extension implies, or {@code null} if unknown. */
  static String expectedFamily(String extension) {
    if (extension == null) {
      return null;
    }
    switch (extension.toLowerCase(Locale.US)) {
      case "pdf":
        return FAMILY_PDF;
      case "jpg":
      case "jpeg":
        return FAMILY_JPEG;
      case "png":
        return FAMILY_PNG;
      case "gif":
        return FAMILY_GIF;
      case "webp":
        return FAMILY_WEBP;
      case "rar":
        return FAMILY_RAR;
      case "7z":
        return FAMILY_7Z;
      case "doc":
      case "xls":
      case "ppt":
        return FAMILY_OLE;
      case "apk":
      case "zip":
      case "docx":
      case "xlsx":
      case "pptx":
      case "jar":
      case "odt":
      case "ods":
      case "odp":
      case "epub":
        return FAMILY_ZIP;
      case "txt":
      case "csv":
      case "json":
      case "xml":
      case "html":
      case "htm":
      case "js":
      case "css":
      case "md":
      case "log":
        return FAMILY_TEXT;
      default:
        return null;
    }
  }

  private static boolean isProbablyText(byte[] b, int n) {
    for (int i = 0; i < n; i++) {
      int c = u(b[i]);
      if (c == 0) {
        return false;
      }
      boolean printable = c == 9 || c == 10 || c == 13 || (c >= 0x20 && c <= 0x7E);
      if (!printable && c < 0x80) {
        return false;
      }
    }
    return true;
  }

  private static int u(byte b) {
    return b & 0xFF;
  }

  private static int indexOf(byte[] haystack, byte[] needle) {
    if (needle.length == 0 || haystack.length < needle.length) {
      return -1;
    }
    int limit = haystack.length - needle.length;
    outer:
    for (int i = 0; i <= limit; i++) {
      for (int j = 0; j < needle.length; j++) {
        if (haystack[i + j] != needle[j]) {
          continue outer;
        }
      }
      return i;
    }
    return -1;
  }

  private static byte[] ascii(String value) {
    try {
      return value.getBytes("US-ASCII");
    } catch (UnsupportedEncodingException e) {
      return value.getBytes();
    }
  }
}
