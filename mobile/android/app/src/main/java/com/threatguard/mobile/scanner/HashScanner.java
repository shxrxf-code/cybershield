package com.threatguard.mobile.scanner;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Streaming SHA-256 hashing. The file is read in fixed-size chunks so even very
 * large files never have to be held in memory, and the user can cancel a long
 * hash while it is still running.
 */
public final class HashScanner {

  private static final int BUFFER_SIZE = 64 * 1024;

  /** Reports how much of the file has been hashed so far. */
  public interface ProgressListener {
    void onProgress(long bytesRead, long totalBytes);
  }

  /** Polled between chunks so a running hash can be aborted. */
  public interface CancellationSignal {
    boolean isCancelled();
  }

  private HashScanner() {
  }

  public static String sha256(File file) throws IOException, NoSuchAlgorithmException {
    return sha256(file, null, null);
  }

  public static String sha256(File file, ProgressListener listener, CancellationSignal signal)
      throws IOException, NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    long total = file.length();
    long read = 0;
    byte[] buffer = new byte[BUFFER_SIZE];
    try (InputStream in = new BufferedInputStream(new FileInputStream(file), BUFFER_SIZE)) {
      int n;
      while ((n = in.read(buffer)) != -1) {
        if (signal != null && signal.isCancelled()) {
          throw new ScanCancelledException();
        }
        digest.update(buffer, 0, n);
        read += n;
        if (listener != null) {
          listener.onProgress(read, total);
        }
      }
    }
    return toHex(digest.digest());
  }

  static String toHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      sb.append(Character.forDigit((b >> 4) & 0xF, 16));
      sb.append(Character.forDigit(b & 0xF, 16));
    }
    return sb.toString();
  }
}
