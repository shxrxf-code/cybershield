package com.shieldguard.ai.data.local.dao;

import android.database.Cursor;
import androidx.annotation.NonNull;
import androidx.room.CoroutinesRoom;
import androidx.room.EntityInsertionAdapter;
import androidx.room.RoomDatabase;
import androidx.room.RoomSQLiteQuery;
import androidx.room.SharedSQLiteStatement;
import androidx.room.util.CursorUtil;
import androidx.room.util.DBUtil;
import androidx.sqlite.db.SupportSQLiteStatement;
import com.shieldguard.ai.data.local.Converters;
import com.shieldguard.ai.data.local.entity.ThreatEntity;
import java.lang.Class;
import java.lang.Exception;
import java.lang.Integer;
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
public final class ThreatDao_Impl implements ThreatDao {
  private final RoomDatabase __db;

  private final EntityInsertionAdapter<ThreatEntity> __insertionAdapterOfThreatEntity;

  private final Converters __converters = new Converters();

  private final SharedSQLiteStatement __preparedStmtOfDeleteThreat;

  private final SharedSQLiteStatement __preparedStmtOfDeleteThreatsByModule;

  private final SharedSQLiteStatement __preparedStmtOfClearAllThreats;

  public ThreatDao_Impl(@NonNull final RoomDatabase __db) {
    this.__db = __db;
    this.__insertionAdapterOfThreatEntity = new EntityInsertionAdapter<ThreatEntity>(__db) {
      @Override
      @NonNull
      protected String createQuery() {
        return "INSERT OR REPLACE INTO `threats` (`id`,`moduleType`,`threatLevel`,`verdict`,`riskScore`,`title`,`description`,`actionTaken`,`rawPayload`,`indicators`,`timestampMs`) VALUES (?,?,?,?,?,?,?,?,?,?,?)";
      }

      @Override
      protected void bind(@NonNull final SupportSQLiteStatement statement,
          @NonNull final ThreatEntity entity) {
        if (entity.getId() == null) {
          statement.bindNull(1);
        } else {
          statement.bindString(1, entity.getId());
        }
        if (entity.getModuleType() == null) {
          statement.bindNull(2);
        } else {
          statement.bindString(2, entity.getModuleType());
        }
        if (entity.getThreatLevel() == null) {
          statement.bindNull(3);
        } else {
          statement.bindString(3, entity.getThreatLevel());
        }
        if (entity.getVerdict() == null) {
          statement.bindNull(4);
        } else {
          statement.bindString(4, entity.getVerdict());
        }
        statement.bindLong(5, entity.getRiskScore());
        if (entity.getTitle() == null) {
          statement.bindNull(6);
        } else {
          statement.bindString(6, entity.getTitle());
        }
        if (entity.getDescription() == null) {
          statement.bindNull(7);
        } else {
          statement.bindString(7, entity.getDescription());
        }
        if (entity.getActionTaken() == null) {
          statement.bindNull(8);
        } else {
          statement.bindString(8, entity.getActionTaken());
        }
        if (entity.getRawPayload() == null) {
          statement.bindNull(9);
        } else {
          statement.bindString(9, entity.getRawPayload());
        }
        final String _tmp = __converters.fromStringList(entity.getIndicators());
        if (_tmp == null) {
          statement.bindNull(10);
        } else {
          statement.bindString(10, _tmp);
        }
        statement.bindLong(11, entity.getTimestampMs());
      }
    };
    this.__preparedStmtOfDeleteThreat = new SharedSQLiteStatement(__db) {
      @Override
      @NonNull
      public String createQuery() {
        final String _query = "DELETE FROM threats WHERE id = ?";
        return _query;
      }
    };
    this.__preparedStmtOfDeleteThreatsByModule = new SharedSQLiteStatement(__db) {
      @Override
      @NonNull
      public String createQuery() {
        final String _query = "DELETE FROM threats WHERE moduleType = ?";
        return _query;
      }
    };
    this.__preparedStmtOfClearAllThreats = new SharedSQLiteStatement(__db) {
      @Override
      @NonNull
      public String createQuery() {
        final String _query = "DELETE FROM threats";
        return _query;
      }
    };
  }

  @Override
  public Object insertThreat(final ThreatEntity threat,
      final Continuation<? super Unit> $completion) {
    return CoroutinesRoom.execute(__db, true, new Callable<Unit>() {
      @Override
      @NonNull
      public Unit call() throws Exception {
        __db.beginTransaction();
        try {
          __insertionAdapterOfThreatEntity.insert(threat);
          __db.setTransactionSuccessful();
          return Unit.INSTANCE;
        } finally {
          __db.endTransaction();
        }
      }
    }, $completion);
  }

  @Override
  public Object deleteThreat(final String threatId, final Continuation<? super Unit> $completion) {
    return CoroutinesRoom.execute(__db, true, new Callable<Unit>() {
      @Override
      @NonNull
      public Unit call() throws Exception {
        final SupportSQLiteStatement _stmt = __preparedStmtOfDeleteThreat.acquire();
        int _argIndex = 1;
        if (threatId == null) {
          _stmt.bindNull(_argIndex);
        } else {
          _stmt.bindString(_argIndex, threatId);
        }
        try {
          __db.beginTransaction();
          try {
            _stmt.executeUpdateDelete();
            __db.setTransactionSuccessful();
            return Unit.INSTANCE;
          } finally {
            __db.endTransaction();
          }
        } finally {
          __preparedStmtOfDeleteThreat.release(_stmt);
        }
      }
    }, $completion);
  }

  @Override
  public Object deleteThreatsByModule(final String moduleType,
      final Continuation<? super Unit> $completion) {
    return CoroutinesRoom.execute(__db, true, new Callable<Unit>() {
      @Override
      @NonNull
      public Unit call() throws Exception {
        final SupportSQLiteStatement _stmt = __preparedStmtOfDeleteThreatsByModule.acquire();
        int _argIndex = 1;
        if (moduleType == null) {
          _stmt.bindNull(_argIndex);
        } else {
          _stmt.bindString(_argIndex, moduleType);
        }
        try {
          __db.beginTransaction();
          try {
            _stmt.executeUpdateDelete();
            __db.setTransactionSuccessful();
            return Unit.INSTANCE;
          } finally {
            __db.endTransaction();
          }
        } finally {
          __preparedStmtOfDeleteThreatsByModule.release(_stmt);
        }
      }
    }, $completion);
  }

  @Override
  public Object clearAllThreats(final Continuation<? super Unit> $completion) {
    return CoroutinesRoom.execute(__db, true, new Callable<Unit>() {
      @Override
      @NonNull
      public Unit call() throws Exception {
        final SupportSQLiteStatement _stmt = __preparedStmtOfClearAllThreats.acquire();
        try {
          __db.beginTransaction();
          try {
            _stmt.executeUpdateDelete();
            __db.setTransactionSuccessful();
            return Unit.INSTANCE;
          } finally {
            __db.endTransaction();
          }
        } finally {
          __preparedStmtOfClearAllThreats.release(_stmt);
        }
      }
    }, $completion);
  }

  @Override
  public Flow<List<ThreatEntity>> getAllThreats() {
    final String _sql = "SELECT * FROM threats ORDER BY timestampMs DESC";
    final RoomSQLiteQuery _statement = RoomSQLiteQuery.acquire(_sql, 0);
    return CoroutinesRoom.createFlow(__db, false, new String[] {"threats"}, new Callable<List<ThreatEntity>>() {
      @Override
      @NonNull
      public List<ThreatEntity> call() throws Exception {
        final Cursor _cursor = DBUtil.query(__db, _statement, false, null);
        try {
          final int _cursorIndexOfId = CursorUtil.getColumnIndexOrThrow(_cursor, "id");
          final int _cursorIndexOfModuleType = CursorUtil.getColumnIndexOrThrow(_cursor, "moduleType");
          final int _cursorIndexOfThreatLevel = CursorUtil.getColumnIndexOrThrow(_cursor, "threatLevel");
          final int _cursorIndexOfVerdict = CursorUtil.getColumnIndexOrThrow(_cursor, "verdict");
          final int _cursorIndexOfRiskScore = CursorUtil.getColumnIndexOrThrow(_cursor, "riskScore");
          final int _cursorIndexOfTitle = CursorUtil.getColumnIndexOrThrow(_cursor, "title");
          final int _cursorIndexOfDescription = CursorUtil.getColumnIndexOrThrow(_cursor, "description");
          final int _cursorIndexOfActionTaken = CursorUtil.getColumnIndexOrThrow(_cursor, "actionTaken");
          final int _cursorIndexOfRawPayload = CursorUtil.getColumnIndexOrThrow(_cursor, "rawPayload");
          final int _cursorIndexOfIndicators = CursorUtil.getColumnIndexOrThrow(_cursor, "indicators");
          final int _cursorIndexOfTimestampMs = CursorUtil.getColumnIndexOrThrow(_cursor, "timestampMs");
          final List<ThreatEntity> _result = new ArrayList<ThreatEntity>(_cursor.getCount());
          while (_cursor.moveToNext()) {
            final ThreatEntity _item;
            final String _tmpId;
            if (_cursor.isNull(_cursorIndexOfId)) {
              _tmpId = null;
            } else {
              _tmpId = _cursor.getString(_cursorIndexOfId);
            }
            final String _tmpModuleType;
            if (_cursor.isNull(_cursorIndexOfModuleType)) {
              _tmpModuleType = null;
            } else {
              _tmpModuleType = _cursor.getString(_cursorIndexOfModuleType);
            }
            final String _tmpThreatLevel;
            if (_cursor.isNull(_cursorIndexOfThreatLevel)) {
              _tmpThreatLevel = null;
            } else {
              _tmpThreatLevel = _cursor.getString(_cursorIndexOfThreatLevel);
            }
            final String _tmpVerdict;
            if (_cursor.isNull(_cursorIndexOfVerdict)) {
              _tmpVerdict = null;
            } else {
              _tmpVerdict = _cursor.getString(_cursorIndexOfVerdict);
            }
            final int _tmpRiskScore;
            _tmpRiskScore = _cursor.getInt(_cursorIndexOfRiskScore);
            final String _tmpTitle;
            if (_cursor.isNull(_cursorIndexOfTitle)) {
              _tmpTitle = null;
            } else {
              _tmpTitle = _cursor.getString(_cursorIndexOfTitle);
            }
            final String _tmpDescription;
            if (_cursor.isNull(_cursorIndexOfDescription)) {
              _tmpDescription = null;
            } else {
              _tmpDescription = _cursor.getString(_cursorIndexOfDescription);
            }
            final String _tmpActionTaken;
            if (_cursor.isNull(_cursorIndexOfActionTaken)) {
              _tmpActionTaken = null;
            } else {
              _tmpActionTaken = _cursor.getString(_cursorIndexOfActionTaken);
            }
            final String _tmpRawPayload;
            if (_cursor.isNull(_cursorIndexOfRawPayload)) {
              _tmpRawPayload = null;
            } else {
              _tmpRawPayload = _cursor.getString(_cursorIndexOfRawPayload);
            }
            final List<String> _tmpIndicators;
            final String _tmp;
            if (_cursor.isNull(_cursorIndexOfIndicators)) {
              _tmp = null;
            } else {
              _tmp = _cursor.getString(_cursorIndexOfIndicators);
            }
            _tmpIndicators = __converters.toStringList(_tmp);
            final long _tmpTimestampMs;
            _tmpTimestampMs = _cursor.getLong(_cursorIndexOfTimestampMs);
            _item = new ThreatEntity(_tmpId,_tmpModuleType,_tmpThreatLevel,_tmpVerdict,_tmpRiskScore,_tmpTitle,_tmpDescription,_tmpActionTaken,_tmpRawPayload,_tmpIndicators,_tmpTimestampMs);
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

  @Override
  public Flow<List<ThreatEntity>> getRecentThreats(final int limit) {
    final String _sql = "SELECT * FROM threats ORDER BY timestampMs DESC LIMIT ?";
    final RoomSQLiteQuery _statement = RoomSQLiteQuery.acquire(_sql, 1);
    int _argIndex = 1;
    _statement.bindLong(_argIndex, limit);
    return CoroutinesRoom.createFlow(__db, false, new String[] {"threats"}, new Callable<List<ThreatEntity>>() {
      @Override
      @NonNull
      public List<ThreatEntity> call() throws Exception {
        final Cursor _cursor = DBUtil.query(__db, _statement, false, null);
        try {
          final int _cursorIndexOfId = CursorUtil.getColumnIndexOrThrow(_cursor, "id");
          final int _cursorIndexOfModuleType = CursorUtil.getColumnIndexOrThrow(_cursor, "moduleType");
          final int _cursorIndexOfThreatLevel = CursorUtil.getColumnIndexOrThrow(_cursor, "threatLevel");
          final int _cursorIndexOfVerdict = CursorUtil.getColumnIndexOrThrow(_cursor, "verdict");
          final int _cursorIndexOfRiskScore = CursorUtil.getColumnIndexOrThrow(_cursor, "riskScore");
          final int _cursorIndexOfTitle = CursorUtil.getColumnIndexOrThrow(_cursor, "title");
          final int _cursorIndexOfDescription = CursorUtil.getColumnIndexOrThrow(_cursor, "description");
          final int _cursorIndexOfActionTaken = CursorUtil.getColumnIndexOrThrow(_cursor, "actionTaken");
          final int _cursorIndexOfRawPayload = CursorUtil.getColumnIndexOrThrow(_cursor, "rawPayload");
          final int _cursorIndexOfIndicators = CursorUtil.getColumnIndexOrThrow(_cursor, "indicators");
          final int _cursorIndexOfTimestampMs = CursorUtil.getColumnIndexOrThrow(_cursor, "timestampMs");
          final List<ThreatEntity> _result = new ArrayList<ThreatEntity>(_cursor.getCount());
          while (_cursor.moveToNext()) {
            final ThreatEntity _item;
            final String _tmpId;
            if (_cursor.isNull(_cursorIndexOfId)) {
              _tmpId = null;
            } else {
              _tmpId = _cursor.getString(_cursorIndexOfId);
            }
            final String _tmpModuleType;
            if (_cursor.isNull(_cursorIndexOfModuleType)) {
              _tmpModuleType = null;
            } else {
              _tmpModuleType = _cursor.getString(_cursorIndexOfModuleType);
            }
            final String _tmpThreatLevel;
            if (_cursor.isNull(_cursorIndexOfThreatLevel)) {
              _tmpThreatLevel = null;
            } else {
              _tmpThreatLevel = _cursor.getString(_cursorIndexOfThreatLevel);
            }
            final String _tmpVerdict;
            if (_cursor.isNull(_cursorIndexOfVerdict)) {
              _tmpVerdict = null;
            } else {
              _tmpVerdict = _cursor.getString(_cursorIndexOfVerdict);
            }
            final int _tmpRiskScore;
            _tmpRiskScore = _cursor.getInt(_cursorIndexOfRiskScore);
            final String _tmpTitle;
            if (_cursor.isNull(_cursorIndexOfTitle)) {
              _tmpTitle = null;
            } else {
              _tmpTitle = _cursor.getString(_cursorIndexOfTitle);
            }
            final String _tmpDescription;
            if (_cursor.isNull(_cursorIndexOfDescription)) {
              _tmpDescription = null;
            } else {
              _tmpDescription = _cursor.getString(_cursorIndexOfDescription);
            }
            final String _tmpActionTaken;
            if (_cursor.isNull(_cursorIndexOfActionTaken)) {
              _tmpActionTaken = null;
            } else {
              _tmpActionTaken = _cursor.getString(_cursorIndexOfActionTaken);
            }
            final String _tmpRawPayload;
            if (_cursor.isNull(_cursorIndexOfRawPayload)) {
              _tmpRawPayload = null;
            } else {
              _tmpRawPayload = _cursor.getString(_cursorIndexOfRawPayload);
            }
            final List<String> _tmpIndicators;
            final String _tmp;
            if (_cursor.isNull(_cursorIndexOfIndicators)) {
              _tmp = null;
            } else {
              _tmp = _cursor.getString(_cursorIndexOfIndicators);
            }
            _tmpIndicators = __converters.toStringList(_tmp);
            final long _tmpTimestampMs;
            _tmpTimestampMs = _cursor.getLong(_cursorIndexOfTimestampMs);
            _item = new ThreatEntity(_tmpId,_tmpModuleType,_tmpThreatLevel,_tmpVerdict,_tmpRiskScore,_tmpTitle,_tmpDescription,_tmpActionTaken,_tmpRawPayload,_tmpIndicators,_tmpTimestampMs);
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

  @Override
  public Flow<Integer> getThreatsCount() {
    final String _sql = "SELECT COUNT(*) FROM threats";
    final RoomSQLiteQuery _statement = RoomSQLiteQuery.acquire(_sql, 0);
    return CoroutinesRoom.createFlow(__db, false, new String[] {"threats"}, new Callable<Integer>() {
      @Override
      @NonNull
      public Integer call() throws Exception {
        final Cursor _cursor = DBUtil.query(__db, _statement, false, null);
        try {
          final Integer _result;
          if (_cursor.moveToFirst()) {
            final Integer _tmp;
            if (_cursor.isNull(0)) {
              _tmp = null;
            } else {
              _tmp = _cursor.getInt(0);
            }
            _result = _tmp;
          } else {
            _result = null;
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
