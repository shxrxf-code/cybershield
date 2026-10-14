package com.threatguard.mobile.scanner;

/** Thrown when an in-flight scan or hash is cancelled by the user. */
public class ScanCancelledException extends RuntimeException {
  public ScanCancelledException() {
    super("The scan was cancelled.");
  }
}
