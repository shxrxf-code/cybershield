package com.threatguard.mobile.scanner;

import android.app.Activity;
import android.content.ClipData;
import android.content.ContentResolver;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;
import android.util.Log;

import com.facebook.react.bridge.ActivityEventListener;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.module.annotations.ReactModule;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * React Native bridge for the on-device file-scanning engine.
 *
 * <p>Files are chosen through the Storage Access Framework, meaning the user
 * explicitly grants access to specific documents — the app never enumerates
 * another app's private storage and asks for no runtime storage permission.
 * Every selected file is copied into the app's own cache, inspected locally and
 * then can be discarded.
 */
@ReactModule(name = FileScannerModule.NAME)
public class FileScannerModule extends ReactContextBaseJavaModule implements ActivityEventListener {

  public static final String NAME = "FileScanner";

  private static final String TAG = "FileScannerModule";
  private static final String EVENT_PROGRESS = "FileScannerProgress";

  private static final int PICK_FILE_REQUEST_CODE = 0x7501;
  private static final int PICK_MULTIPLE_FILES_REQUEST_CODE = 0x7502;

  private static final String[] SUPPORTED_MIME_TYPES = {
      "application/pdf",
      "application/vnd.android.package-archive",
      "image/*",
      "text/*",
      "application/zip",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "application/vnd.ms-excel",
      "application/octet-stream",
  };

  private static final class CachedFile {
    final File file;
    final String displayName;
    final String mimeType;

    CachedFile(File file, String displayName, String mimeType) {
      this.file = file;
      this.displayName = displayName;
      this.mimeType = mimeType;
    }
  }

  private final ExecutorService executor = Executors.newSingleThreadExecutor();
  private final AtomicBoolean cancelled = new AtomicBoolean(false);
  private final Map<String, CachedFile> cache = new HashMap<>();

  private Promise pickPromise;

  public FileScannerModule(ReactApplicationContext reactContext) {
    super(reactContext);
    reactContext.addActivityEventListener(this);
  }

  @Override
  public String getName() {
    return NAME;
  }

  @Override
  public Map<String, Object> getConstants() {
    Map<String, Object> constants = new HashMap<>();
    constants.put("MAX_FILE_SIZE", FileScanner.DEFAULT_MAX_FILE_SIZE);
    constants.put("MAX_CONTENT_SCAN_BYTES", FileScanner.DEFAULT_MAX_CONTENT_SCAN_BYTES);
    constants.put("SUPPORTED_MIME_TYPES", toWritableArray(SUPPORTED_MIME_TYPES));
    constants.put("ENGINE_VERSION", 1);
    return constants;
  }

  /**
   * Opens the system document picker. Resolves with the list of content URIs the
   * user selected, or rejects with {@code E_PICK_CANCELLED} if they dismissed it.
   */
  @ReactMethod
  public void pickFile(boolean multiple, Promise promise) {
    if (pickPromise != null) {
      promise.reject("E_PICK_IN_PROGRESS", "A file picker is already open.");
      return;
    }

    Activity activity = getCurrentActivity();
    if (activity == null) {
      promise.reject("E_NO_ACTIVITY", "No foreground activity to show the file picker.");
      return;
    }

    Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
    intent.addCategory(Intent.CATEGORY_OPENABLE);
    intent.setType("*/*");
    intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, multiple);
    intent.putExtra(Intent.EXTRA_MIME_TYPES, SUPPORTED_MIME_TYPES);

    pickPromise = promise;
    try {
      activity.startActivityForResult(
          intent, multiple ? PICK_MULTIPLE_FILES_REQUEST_CODE : PICK_FILE_REQUEST_CODE);
    } catch (Exception e) {
      pickPromise = null;
      promise.reject("E_PICK_LAUNCH", "Could not open the system file picker.", e);
    }
  }

  /** Hashes a file selected through the picker. */
  @ReactMethod
  public void computeFileHash(final String fileUri, final Promise promise) {
    cancelled.set(false);
    executor.execute(() -> {
      try {
        CachedFile cached = resolveCachedFile(fileUri);
        String hash = HashScanner.sha256(
            cached.file,
            (read, total) -> {
              if (total > 0) {
                emitProgress(fileUri, "hashing", (int) (read * 100 / total));
              }
            },
            cancelled::get);
        emitProgress(fileUri, "done", 100);

        WritableMap result = Arguments.createMap();
        result.putString("uri", fileUri);
        result.putString("hash", hash);
        promise.resolve(result);
      } catch (ScanCancelledException e) {
        promise.reject("E_CANCELLED", "The scan was cancelled.");
      } catch (FileTooLargeException e) {
        promise.reject("E_FILE_TOO_LARGE", e.getMessage());
      } catch (Exception e) {
        Log.e(TAG, "Failed to hash file", e);
        promise.reject("E_HASH_FAILED", messageOf(e, "Failed to hash the file."), e);
      }
    });
  }

  /** Copies the selected file into the app cache and runs the local engine. */
  @ReactMethod
  public void scanFile(final String fileUri, final Promise promise) {
    cancelled.set(false);
    executor.execute(() -> {
      try {
        CachedFile cached = resolveCachedFile(fileUri);
        FileScanner.Options options = new FileScanner.Options();
        FileScanner.Inspection inspection = FileScanner.inspect(
            cached.file,
            cached.mimeType,
            options,
            (phase, percent) -> emitProgress(fileUri, phase, percent),
            cancelled::get);
        emitProgress(fileUri, "done", 100);

        WritableMap result = Arguments.createMap();
        result.putString("uri", fileUri);
        result.putString("fileName", cached.displayName);
        result.putDouble("fileSize", inspection.fileSize);
        result.putString("mimeType", inspection.mimeType);
        result.putString("extension", inspection.extension == null ? "" : inspection.extension);
        if (inspection.magicType != null) {
          result.putString("magicType", inspection.magicType);
        }
        if (inspection.sha256 != null) {
          result.putString("sha256", inspection.sha256);
        }
        result.putBoolean("truncated", inspection.truncated);
        result.putDouble("durationMs", inspection.durationMs);
        result.putMap("scanResult", inspection.scanResult.toWritableMap());
        promise.resolve(result);
      } catch (ScanCancelledException e) {
        promise.reject("E_CANCELLED", "The scan was cancelled.");
      } catch (FileTooLargeException e) {
        promise.reject("E_FILE_TOO_LARGE", e.getMessage());
      } catch (Exception e) {
        Log.e(TAG, "Failed to scan file", e);
        promise.reject("E_SCAN_FAILED", messageOf(e, "Failed to scan the file."), e);
      }
    });
  }

  /** Requests that the in-flight scan/hash stop as soon as it can. */
  @ReactMethod
  public void cancelScan(Promise promise) {
    cancelled.set(true);
    promise.resolve(true);
  }

  /** Deletes every cached copy the module has made. */
  @ReactMethod
  public void clearCache(Promise promise) {
    for (CachedFile cached : cache.values()) {
      if (cached.file != null && cached.file.exists() && !cached.file.delete()) {
        Log.w(TAG, "Could not delete cached file: " + cached.file.getAbsolutePath());
      }
    }
    cache.clear();
    promise.resolve(true);
  }

  // Required by NativeEventEmitter so progress subscriptions can be registered.
  @ReactMethod
  public void addListener(String eventName) {
    // no-op
  }

  @ReactMethod
  public void removeListeners(Integer count) {
    // no-op
  }

  @Override
  public void onActivityResult(Activity activity, int requestCode, int resultCode, Intent data) {
    if (requestCode != PICK_FILE_REQUEST_CODE && requestCode != PICK_MULTIPLE_FILES_REQUEST_CODE) {
      return;
    }

    Promise promise = pickPromise;
    pickPromise = null;
    if (promise == null) {
      return;
    }

    if (resultCode != Activity.RESULT_OK || data == null) {
      promise.reject("E_PICK_CANCELLED", "No file was selected.");
      return;
    }

    ArrayList<String> uris = new ArrayList<>();
    if (data.getData() != null) {
      uris.add(data.getData().toString());
    }
    ClipData clip = data.getClipData();
    if (clip != null) {
      for (int i = 0; i < clip.getItemCount(); i++) {
        Uri uri = clip.getItemAt(i).getUri();
        if (uri != null) {
          uris.add(uri.toString());
        }
      }
    }

    if (uris.isEmpty()) {
      promise.reject("E_PICK_EMPTY", "The picker returned no files.");
      return;
    }

    WritableArray array = Arguments.createArray();
    for (String uri : uris) {
      array.pushString(uri);
    }
    promise.resolve(array);
  }

  @Override
  public void onNewIntent(Intent intent) {
    // Not used: the picker returns through onActivityResult.
  }

  @Override
  public void invalidate() {
    cancelled.set(true);
    executor.shutdownNow();
    getReactApplicationContext().removeActivityEventListener(this);
    super.invalidate();
  }

  private CachedFile resolveCachedFile(String fileUri) throws IOException {
    CachedFile existing = cache.get(fileUri);
    if (existing != null && existing.file.exists()) {
      return existing;
    }

    Uri uri = Uri.parse(fileUri);
    ContentResolver resolver = getReactApplicationContext().getContentResolver();
    String displayName = queryDisplayName(resolver, uri);
    String mimeType = resolver.getType(uri);
    long reportedSize = querySize(resolver, uri);

    if (reportedSize > FileScanner.DEFAULT_MAX_FILE_SIZE) {
      throw new FileTooLargeException();
    }

    File target = new File(
        getReactApplicationContext().getCacheDir(),
        "scan_" + UUID.randomUUID().toString().replace("-", "") + "_" + sanitize(displayName));

    try (InputStream in = resolver.openInputStream(uri)) {
      if (in == null) {
        throw new IOException("The selected file could not be opened.");
      }
      copyWithLimit(in, target, FileScanner.DEFAULT_MAX_FILE_SIZE);
    } catch (FileTooLargeException e) {
      //noinspection ResultOfMethodCallIgnored
      target.delete();
      throw e;
    } catch (IOException e) {
      //noinspection ResultOfMethodCallIgnored
      target.delete();
      throw e;
    }

    CachedFile cached = new CachedFile(target, displayName, mimeType);
    cache.put(fileUri, cached);
    return cached;
  }

  private static void copyWithLimit(InputStream in, File target, long maxBytes) throws IOException {
    long written = 0;
    byte[] buffer = new byte[64 * 1024];
    try (OutputStream out = new FileOutputStream(target)) {
      int n;
      while ((n = in.read(buffer)) != -1) {
        written += n;
        if (written > maxBytes) {
          throw new FileTooLargeException();
        }
        out.write(buffer, 0, n);
      }
    }
  }

  private String queryDisplayName(ContentResolver resolver, Uri uri) {
    Cursor cursor = null;
    try {
      cursor = resolver.query(uri, new String[]{OpenableColumns.DISPLAY_NAME}, null, null, null);
      if (cursor != null && cursor.moveToFirst()) {
        int index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
        if (index >= 0) {
          String name = cursor.getString(index);
          if (name != null && !name.isEmpty()) {
            return name;
          }
        }
      }
    } catch (Exception e) {
      Log.w(TAG, "Could not read the file name", e);
    } finally {
      if (cursor != null) {
        cursor.close();
      }
    }
    String segment = uri.getLastPathSegment();
    return segment == null ? "selected-file" : segment;
  }

  private long querySize(ContentResolver resolver, Uri uri) {
    Cursor cursor = null;
    try {
      cursor = resolver.query(uri, new String[]{OpenableColumns.SIZE}, null, null, null);
      if (cursor != null && cursor.moveToFirst()) {
        int index = cursor.getColumnIndex(OpenableColumns.SIZE);
        if (index >= 0 && !cursor.isNull(index)) {
          return cursor.getLong(index);
        }
      }
    } catch (Exception e) {
      Log.w(TAG, "Could not read the file size", e);
    } finally {
      if (cursor != null) {
        cursor.close();
      }
    }
    return -1;
  }

  private void emitProgress(String uri, String phase, int percent) {
    ReactApplicationContext context = getReactApplicationContext();
    if (!context.hasActiveReactInstance()) {
      return;
    }
    WritableMap payload = Arguments.createMap();
    payload.putString("uri", uri);
    payload.putString("phase", phase);
    payload.putInt("percent", Math.max(0, Math.min(100, percent)));
    try {
      context.emitDeviceEvent(EVENT_PROGRESS, payload);
    } catch (Exception e) {
      Log.w(TAG, "Could not emit progress", e);
    }
  }

  private static String sanitize(String name) {
    if (name == null || name.isEmpty()) {
      return "selected-file";
    }
    return name.replace('/', '_').replace('\\', '_');
  }

  private static String messageOf(Exception e, String fallback) {
    String message = e.getMessage();
    return message == null || message.isEmpty() ? fallback : message;
  }

  private static WritableArray toWritableArray(String[] values) {
    WritableArray array = Arguments.createArray();
    for (String value : values) {
      array.pushString(value);
    }
    return array;
  }

  /** Raised when a selected file exceeds the configurable scan limit. */
  static class FileTooLargeException extends IOException {
    FileTooLargeException() {
      super("File is larger than the "
          + (FileScanner.DEFAULT_MAX_FILE_SIZE / (1024 * 1024)) + " MB scan limit.");
    }
  }
}
