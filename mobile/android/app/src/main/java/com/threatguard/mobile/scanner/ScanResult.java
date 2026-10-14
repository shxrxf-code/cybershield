package com.threatguard.mobile.scanner;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;

import java.util.ArrayList;
import java.util.List;

/**
 * Structured result of a local file inspection.
 *
 * A file is only ever reported as a {@link #STATUS_THREAT} when a definitive
 * signature matched (a "high" severity finding). Everything weaker — a
 * mismatched extension, a PDF that carries JavaScript, an APK missing its
 * manifest — is at most {@link #STATUS_SUSPICIOUS}. Informational findings do
 * not change the status at all, so an empty or unusual file is never called
 * malicious.
 */
public final class ScanResult {

  public static final String STATUS_CLEAN = "clean";
  public static final String STATUS_SUSPICIOUS = "suspicious";
  public static final String STATUS_THREAT = "threat";
  public static final String STATUS_ERROR = "error";

  public static final String SEVERITY_HIGH = "high";
  public static final String SEVERITY_MEDIUM = "medium";
  public static final String SEVERITY_LOW = "low";
  public static final String SEVERITY_INFO = "info";

  public static final class Finding {
    public final String code;
    public final String message;
    public final String severity;

    Finding(String code, String message, String severity) {
      this.code = code;
      this.message = message;
      this.severity = severity;
    }
  }

  private final List<Finding> findings = new ArrayList<>();
  private boolean truncated = false;
  private String errorCode;
  private String errorMessage;

  public void add(String code, String message, String severity) {
    for (Finding existing : findings) {
      if (existing.code.equals(code)) {
        return; // de-duplicate by code
      }
    }
    findings.add(new Finding(code, message, severity));
  }

  public List<Finding> getFindings() {
    return findings;
  }

  public boolean hasHighSeverity() {
    for (Finding f : findings) {
      if (SEVERITY_HIGH.equals(f.severity)) {
        return true;
      }
    }
    return false;
  }

  private boolean hasActionableFinding() {
    for (Finding f : findings) {
      if (SEVERITY_MEDIUM.equals(f.severity) || SEVERITY_LOW.equals(f.severity)) {
        return true;
      }
    }
    return false;
  }

  public void markTruncated() {
    truncated = true;
  }

  public boolean isTruncated() {
    return truncated;
  }

  public void setError(String code, String message) {
    this.errorCode = code;
    this.errorMessage = message;
  }

  public boolean isError() {
    return errorCode != null;
  }

  public String getStatus() {
    if (isError()) {
      return STATUS_ERROR;
    }
    if (hasHighSeverity()) {
      return STATUS_THREAT;
    }
    if (hasActionableFinding()) {
      return STATUS_SUSPICIOUS;
    }
    return STATUS_CLEAN;
  }

  private String buildDetails() {
    if (isError()) {
      return errorMessage == null ? "The file could not be inspected." : errorMessage;
    }

    int actionable = 0;
    int informational = 0;
    for (Finding f : findings) {
      if (SEVERITY_INFO.equals(f.severity)) {
        informational++;
      } else {
        actionable++;
      }
    }

    if (actionable == 0 && informational == 0) {
      return truncated
          ? "No known signatures matched in the portion inspected."
          : "No known signatures matched.";
    }
    if (actionable == 0) {
      String notes = informational == 1 ? "1 note" : informational + " notes";
      return "No known signatures matched (" + notes + ").";
    }

    StringBuilder sb = new StringBuilder();
    sb.append(actionable).append(actionable == 1 ? " finding" : " findings");
    if (informational > 0) {
      sb.append(" and ").append(informational)
          .append(informational == 1 ? " note" : " notes");
    }
    if (truncated) {
      sb.append(" (partial scan)");
    }
    return sb.toString();
  }

  public WritableMap toWritableMap() {
    WritableMap map = Arguments.createMap();
    map.putString("status", getStatus());
    map.putString("details", buildDetails());
    map.putBoolean("truncated", truncated);

    WritableArray findingsArray = Arguments.createArray();
    WritableArray codes = Arguments.createArray();
    for (Finding f : findings) {
      WritableMap fm = Arguments.createMap();
      fm.putString("code", f.code);
      fm.putString("message", f.message);
      fm.putString("severity", f.severity);
      findingsArray.pushMap(fm);
      codes.pushString(f.code);
    }
    map.putArray("findings", findingsArray);
    // `threats` is kept for callers that only need the finding codes.
    map.putArray("threats", codes);
    if (isError()) {
      map.putString("errorCode", errorCode);
    }
    return map;
  }
}
