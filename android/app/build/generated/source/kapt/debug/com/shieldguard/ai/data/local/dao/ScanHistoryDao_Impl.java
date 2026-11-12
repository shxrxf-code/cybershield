package com.shieldguard.ai.data.local.dao;

import android.database.Cursor;
import androidx.annotation.NonNull;
import androidx.room.CoroutinesRoom;
import androidx.room.EntityInsertionAdapter;
import androidx.room.RoomDatabase;
import androidx.room.RoomSQLiteQuery;
import androidx.room.util.CursorUtil;
import androidx.room.util.DBUtil;
import androidx.sqlite.db.SupportSQLiteStatement;
import com.shieldguard.ai.data.local.Converters;
import com.shieldguard.ai.data.local.entity.ScanHistoryEntity;
import java.lang.Class;
import java.lang.Exception;
import java.lang.Object;
import java.lang.Override;
import java.lang.String;
import java.lang.SuppressWarnings;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import javax.annotation.processing.Generated;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlinx.coroutines.flow.Flow;

@Generated("androidx.room.RoomProcessor")
@SuppressWarnings({"unchecked", "deprecation"})
public final class ScanHistoryDao_Impl implements ScanHistoryDao {
  private final RoomDatabase __db;

  private final EntityInsertionAdapter<ScanHistoryEntity> __insertionAdapterOfScanHistoryEntity;

  private final Converters __converters = new Converters();

  public ScanHistoryDao_Impl(@NonNull final RoomDatabase __db) {
    this.__db = __db;
    this.__insertionAdapterOfScanHistoryEntity = new EntityInsertionAdapter<ScanHistoryEntity>(__db) {
      @Override
      @NonNull
      protected String createQuery() {
        return "INSERT OR REPLACE INTO `scan_history` (`scanId`,`scanType`,`status`,`riskScore`,`findingsCount`,`scannedItemsCount`,`findings`,`durationMs`,`timestampMs`) VALUES (?,?,?,?,?,?,?,?,?)";
      }

      @Override
      protected void bind(@NonNull final SupportSQLiteStatement statement,
          @NonNull final ScanHistoryEntity entity) {
        if (entity.getScanId() == null) {
          statement.bindNull(1);
        } else {
          statement.bindString(1, entity.getScanId());
        }
        if (entity.getScanType() == null) {
          statement.bindNull(2);
        } else {
          statement.bindString(2, entity.getScanType());
        }
        if (entity.getStatus() == null) {
          statement.bindNull(3);
        } else {
          statement.bindString(3, entity.getStatus());
        }
        statement.bindLong(4, entity.getRiskScore());
        statement.bindLong(5, entity.getFindingsCount());
        statement.bindLong(6, entity.getScannedItemsCount());
        final String _tmp = __converters.fromStringList(entity.getFindings());
        if (_tmp == null) {
          statement.bindNull(7);
        } else {
          statement.bindString(7, _tmp);
        }
        statement.bindLong(8, entity.getDurationMs());
        statement.bindLong(9, entity.getTimestampMs());
      }
    };
  }

  @Override
  public Object insertScan(final ScanHistoryEntity scan, final Continuation<? super Unit> arg1) {
    return CoroutinesRoom.execute(__db, true, new Callable<Unit>() {
      @Override
      @NonNull
      public Unit call() throws Exception {
        __db.beginTransaction();
        try {
          __insertionAdapterOfScanHistoryEntity.insert(scan);
          __db.setTransactionSuccessful();
          return Unit.INSTANCE;
        } finally {
          __db.endTransaction();
        }
      }
    }, arg1);
  }

  @Override
  public Flow<List<ScanHistoryEntity>> getAllScans() {
    final String _sql = "SELECT * FROM scan_history ORDER BY timestampMs DESC";
    final RoomSQLiteQuery _statement = RoomSQLiteQuery.acquire(_sql, 0);
    return CoroutinesRoom.createFlow(__db, false, new String[] {"scan_history"}, new Callable<List<ScanHistoryEntity>>() {
      @Override
      @NonNull
      public List<ScanHistoryEntity> call() throws Exception {
        final Cursor _cursor = DBUtil.query(__db, _statement, false, null);
        try {
          final int _cursorIndexOfScanId = CursorUtil.getColumnIndexOrThrow(_cursor, "scanId");
          final int _cursorIndexOfScanType = CursorUtil.getColumnIndexOrThrow(_cursor, "scanType");
          final int _cursorIndexOfStatus = CursorUtil.getColumnIndexOrThrow(_cursor, "status");
          final int _cursorIndexOfRiskScore = CursorUtil.getColumnIndexOrThrow(_cursor, "riskScore");
          final int _cursorIndexOfFindingsCount = CursorUtil.getColumnIndexOrThrow(_cursor, "findingsCount");
          final int _cursorIndexOfScannedItemsCount = CursorUtil.getColumnIndexOrThrow(_cursor, "scannedItemsCount");
          final int _cursorIndexOfFindings = CursorUtil.getColumnIndexOrThrow(_cursor, "findings");
          final int _cursorIndexOfDurationMs = CursorUtil.getColumnIndexOrThrow(_cursor, "durationMs");
          final int _cursorIndexOfTimestampMs = CursorUtil.getColumnIndexOrThrow(_cursor, "timestampMs");
          final List<ScanHistoryEntity> _result = new ArrayList<ScanHistoryEntity>(_cursor.getCount());
          while (_cursor.moveToNext()) {
            final ScanHistoryEntity _item;
            final String _tmpScanId;
            if (_cursor.isNull(_cursorIndexOfScanId)) {
              _tmpScanId = null;
            } else {
              _tmpScanId = _cursor.getString(_cursorIndexOfScanId);
            }
            final String _tmpScanType;
            if (_cursor.isNull(_cursorIndexOfScanType)) {
              _tmpScanType = null;
            } else {
              _tmpScanType = _cursor.getString(_cursorIndexOfScanType);
            }
            final String _tmpStatus;
            if (_cursor.isNull(_cursorIndexOfStatus)) {
              _tmpStatus = null;
            } else {
              _tmpStatus = _cursor.getString(_cursorIndexOfStatus);
            }
            final int _tmpRiskScore;
            _tmpRiskScore = _cursor.getInt(_cursorIndexOfRiskScore);
            final int _tmpFindingsCount;
            _tmpFindingsCount = _cursor.getInt(_cursorIndexOfFindingsCount);
            final int _tmpScannedItemsCount;
            _tmpScannedItemsCount = _cursor.getInt(_cursorIndexOfScannedItemsCount);
            final List<String> _tmpFindings;
            final String _tmp;
            if (_cursor.isNull(_cursorIndexOfFindings)) {
              _tmp = null;
            } else {
              _tmp = _cursor.getString(_cursorIndexOfFindings);
            }
            _tmpFindings = __converters.toStringList(_tmp);
            final long _tmpDurationMs;
            _tmpDurationMs = _cursor.getLong(_cursorIndexOfDurationMs);
            final long _tmpTimestampMs;
            _tmpTimestampMs = _cursor.getLong(_cursorIndexOfTimestampMs);
            _item = new ScanHistoryEntity(_tmpScanId,_tmpScanType,_tmpStatus,_tmpRiskScore,_tmpFindingsCount,_tmpScannedItemsCount,_tmpFindings,_tmpDurationMs,_tmpTimestampMs);
            _result.add(_item);
          }
          return _result;
        } finally {
          _cursor.close();
        }
      }

      @Override
      protected void finalize() {
        _statement.release();
      }
    });
  }

  @NonNull
  public static List<Class<?>> getRequiredConverters() {
    return Collections.emptyList();
  }
}
