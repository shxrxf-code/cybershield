package com.shieldguard.ai.data.local;

import androidx.annotation.NonNull;
import androidx.room.DatabaseConfiguration;
import androidx.room.InvalidationTracker;
import androidx.room.RoomDatabase;
import androidx.room.RoomOpenHelper;
import androidx.room.migration.AutoMigrationSpec;
import androidx.room.migration.Migration;
import androidx.room.util.DBUtil;
import androidx.room.util.TableInfo;
import androidx.sqlite.db.SupportSQLiteDatabase;
import androidx.sqlite.db.SupportSQLiteOpenHelper;
import com.shieldguard.ai.data.local.dao.ScanHistoryDao;
import com.shieldguard.ai.data.local.dao.ScanHistoryDao_Impl;
import com.shieldguard.ai.data.local.dao.ThreatDao;
import com.shieldguard.ai.data.local.dao.ThreatDao_Impl;
import java.lang.Class;
import java.lang.Override;
import java.lang.String;
import java.lang.SuppressWarnings;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.annotation.processing.Generated;

@Generated("androidx.room.RoomProcessor")
@SuppressWarnings({"unchecked", "deprecation"})
public final class ShieldGuardDatabase_Impl extends ShieldGuardDatabase {
  private volatile ThreatDao _threatDao;

  private volatile ScanHistoryDao _scanHistoryDao;

  @Override
  @NonNull
  protected SupportSQLiteOpenHelper createOpenHelper(@NonNull final DatabaseConfiguration config) {
    final SupportSQLiteOpenHelper.Callback _openCallback = new RoomOpenHelper(config, new RoomOpenHelper.Delegate(1) {
      @Override
      public void createAllTables(@NonNull final SupportSQLiteDatabase db) {
        db.execSQL("CREATE TABLE IF NOT EXISTS `threats` (`id` TEXT NOT NULL, `moduleType` TEXT NOT NULL, `threatLevel` TEXT NOT NULL, `verdict` TEXT NOT NULL, `riskScore` INTEGER NOT NULL, `title` TEXT NOT NULL, `description` TEXT NOT NULL, `actionTaken` TEXT NOT NULL, `rawPayload` TEXT NOT NULL, `indicators` TEXT NOT NULL, `timestampMs` INTEGER NOT NULL, PRIMARY KEY(`id`))");
        db.execSQL("CREATE INDEX IF NOT EXISTS `index_threats_moduleType` ON `threats` (`moduleType`)");
        db.execSQL("CREATE INDEX IF NOT EXISTS `index_threats_threatLevel` ON `threats` (`threatLevel`)");
        db.execSQL("CREATE INDEX IF NOT EXISTS `index_threats_timestampMs` ON `threats` (`timestampMs`)");
        db.execSQL("CREATE TABLE IF NOT EXISTS `scan_history` (`scanId` TEXT NOT NULL, `scanType` TEXT NOT NULL, `status` TEXT NOT NULL, `riskScore` INTEGER NOT NULL, `findingsCount` INTEGER NOT NULL, `scannedItemsCount` INTEGER NOT NULL, `findings` TEXT NOT NULL, `durationMs` INTEGER NOT NULL, `timestampMs` INTEGER NOT NULL, PRIMARY KEY(`scanId`))");
        db.execSQL("CREATE INDEX IF NOT EXISTS `index_scan_history_timestampMs` ON `scan_history` (`timestampMs`)");
        db.execSQL("CREATE TABLE IF NOT EXISTS room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)");
        db.execSQL("INSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, 'aef2d3a6aec91c58b2b2c803d7867848')");
      }

      @Override
      public void dropAllTables(@NonNull final SupportSQLiteDatabase db) {
        db.execSQL("DROP TABLE IF EXISTS `threats`");
        db.execSQL("DROP TABLE IF EXISTS `scan_history`");
        final List<? extends RoomDatabase.Callback> _callbacks = mCallbacks;
        if (_callbacks != null) {
          for (RoomDatabase.Callback _callback : _callbacks) {
            _callback.onDestructiveMigration(db);
          }
        }
      }

      @Override
      public void onCreate(@NonNull final SupportSQLiteDatabase db) {
        final List<? extends RoomDatabase.Callback> _callbacks = mCallbacks;
        if (_callbacks != null) {
          for (RoomDatabase.Callback _callback : _callbacks) {
            _callback.onCreate(db);
          }
        }
      }

      @Override
      public void onOpen(@NonNull final SupportSQLiteDatabase db) {
        mDatabase = db;
        internalInitInvalidationTracker(db);
        final List<? extends RoomDatabase.Callback> _callbacks = mCallbacks;
        if (_callbacks != null) {
          for (RoomDatabase.Callback _callback : _callbacks) {
            _callback.onOpen(db);
          }
        }
      }

      @Override
      public void onPreMigrate(@NonNull final SupportSQLiteDatabase db) {
        DBUtil.dropFtsSyncTriggers(db);
      }

      @Override
      public void onPostMigrate(@NonNull final SupportSQLiteDatabase db) {
      }

      @Override
      @NonNull
      public RoomOpenHelper.ValidationResult onValidateSchema(
          @NonNull final SupportSQLiteDatabase db) {
        final HashMap<String, TableInfo.Column> _columnsThreats = new HashMap<String, TableInfo.Column>(11);
        _columnsThreats.put("id", new TableInfo.Column("id", "TEXT", true, 1, null, TableInfo.CREATED_FROM_ENTITY));
        _columnsThreats.put("moduleType", new TableInfo.Column("moduleType", "TEXT", true, 0, null, TableInfo.CREATED_FROM_ENTITY));
        _columnsThreats.put("threatLevel", new TableInfo.Column("threatLevel", "TEXT", true, 0, null, TableInfo.CREATED_FROM_ENTITY));
        _columnsThreats.put("verdict", new TableInfo.Column("verdict", "TEXT", true, 0, null, TableInfo.CREATED_FROM_ENTITY));
        _columnsThreats.put("riskScore", new TableInfo.Column("riskScore", "INTEGER", true, 0, null, TableInfo.CREATED_FROM_ENTITY));
        _columnsThreats.put("title", new TableInfo.Column("title", "TEXT", true, 0, null, TableInfo.CREATED_FROM_ENTITY));
        _columnsThreats.put("description", new TableInfo.Column("description", "TEXT", true, 0, null, TableInfo.CREATED_FROM_ENTITY));
        _columnsThreats.put("actionTaken", new TableInfo.Column("actionTaken", "TEXT", true, 0, null, TableInfo.CREATED_FROM_ENTITY));
        _columnsThreats.put("rawPayload", new TableInfo.Column("rawPayload", "TEXT", true, 0, null, TableInfo.CREATED_FROM_ENTITY));
        _columnsThreats.put("indicators", new TableInfo.Column("indicators", "TEXT", true, 0, null, TableInfo.CREATED_FROM_ENTITY));
        _columnsThreats.put("timestampMs", new TableInfo.Column("timestampMs", "INTEGER", true, 0, null, TableInfo.CREATED_FROM_ENTITY));
        final HashSet<TableInfo.ForeignKey> _foreignKeysThreats = new HashSet<TableInfo.ForeignKey>(0);
        final HashSet<TableInfo.Index> _indicesThreats = new HashSet<TableInfo.Index>(3);
        _indicesThreats.add(new TableInfo.Index("index_threats_moduleType", false, Arrays.asList("moduleType"), Arrays.asList("ASC")));
        _indicesThreats.add(new TableInfo.Index("index_threats_threatLevel", false, Arrays.asList("threatLevel"), Arrays.asList("ASC")));
        _indicesThreats.add(new TableInfo.Index("index_threats_timestampMs", false, Arrays.asList("timestampMs"), Arrays.asList("ASC")));
        final TableInfo _infoThreats = new TableInfo("threats", _columnsThreats, _foreignKeysThreats, _indicesThreats);
        final TableInfo _existingThreats = TableInfo.read(db, "threats");
        if (!_infoThreats.equals(_existingThreats)) {
          return new RoomOpenHelper.ValidationResult(false, "threats(com.shieldguard.ai.data.local.entity.ThreatEntity).\n"
                  + " Expected:\n" + _infoThreats + "\n"
                  + " Found:\n" + _existingThreats);
        }
        final HashMap<String, TableInfo.Column> _columnsScanHistory = new HashMap<String, TableInfo.Column>(9);
        _columnsScanHistory.put("scanId", new TableInfo.Column("scanId", "TEXT", true, 1, null, TableInfo.CREATED_FROM_ENTITY));
        _columnsScanHistory.put("scanType", new TableInfo.Column("scanType", "TEXT", true, 0, null, TableInfo.CREATED_FROM_ENTITY));
        _columnsScanHistory.put("status", new TableInfo.Column("status", "TEXT", true, 0, null, TableInfo.CREATED_FROM_ENTITY));
        _columnsScanHistory.put("riskScore", new TableInfo.Column("riskScore", "INTEGER", true, 0, null, TableInfo.CREATED_FROM_ENTITY));
        _columnsScanHistory.put("findingsCount", new TableInfo.Column("findingsCount", "INTEGER", true, 0, null, TableInfo.CREATED_FROM_ENTITY));
        _columnsScanHistory.put("scannedItemsCount", new TableInfo.Column("scannedItemsCount", "INTEGER", true, 0, null, TableInfo.CREATED_FROM_ENTITY));
        _columnsScanHistory.put("findings", new TableInfo.Column("findings", "TEXT", true, 0, null, TableInfo.CREATED_FROM_ENTITY));
        _columnsScanHistory.put("durationMs", new TableInfo.Column("durationMs", "INTEGER", true, 0, null, TableInfo.CREATED_FROM_ENTITY));
        _columnsScanHistory.put("timestampMs", new TableInfo.Column("timestampMs", "INTEGER", true, 0, null, TableInfo.CREATED_FROM_ENTITY));
        final HashSet<TableInfo.ForeignKey> _foreignKeysScanHistory = new HashSet<TableInfo.ForeignKey>(0);
        final HashSet<TableInfo.Index> _indicesScanHistory = new HashSet<TableInfo.Index>(1);
        _indicesScanHistory.add(new TableInfo.Index("index_scan_history_timestampMs", false, Arrays.asList("timestampMs"), Arrays.asList("ASC")));
        final TableInfo _infoScanHistory = new TableInfo("scan_history", _columnsScanHistory, _foreignKeysScanHistory, _indicesScanHistory);
        final TableInfo _existingScanHistory = TableInfo.read(db, "scan_history");
        if (!_infoScanHistory.equals(_existingScanHistory)) {
          return new RoomOpenHelper.ValidationResult(false, "scan_history(com.shieldguard.ai.data.local.entity.ScanHistoryEntity).\n"
                  + " Expected:\n" + _infoScanHistory + "\n"
                  + " Found:\n" + _existingScanHistory);
        }
        return new RoomOpenHelper.ValidationResult(true, null);
      }
    }, "aef2d3a6aec91c58b2b2c803d7867848", "75b939b47712264ab33b2390ade9911c");
    final SupportSQLiteOpenHelper.Configuration _sqliteConfig = SupportSQLiteOpenHelper.Configuration.builder(config.context).name(config.name).callback(_openCallback).build();
    final SupportSQLiteOpenHelper _helper = config.sqliteOpenHelperFactory.create(_sqliteConfig);
    return _helper;
  }

  @Override
  @NonNull
  protected InvalidationTracker createInvalidationTracker() {
    final HashMap<String, String> _shadowTablesMap = new HashMap<String, String>(0);
    final HashMap<String, Set<String>> _viewTables = new HashMap<String, Set<String>>(0);
    return new InvalidationTracker(this, _shadowTablesMap, _viewTables, "threats","scan_history");
  }

  @Override
  public void clearAllTables() {
    super.assertNotMainThread();
    final SupportSQLiteDatabase _db = super.getOpenHelper().getWritableDatabase();
    try {
      super.beginTransaction();
      _db.execSQL("DELETE FROM `threats`");
      _db.execSQL("DELETE FROM `scan_history`");
      super.setTransactionSuccessful();
    } finally {
      super.endTransaction();
      _db.query("PRAGMA wal_checkpoint(FULL)").close();
      if (!_db.inTransaction()) {
        _db.execSQL("VACUUM");
      }
    }
  }

  @Override
  @NonNull
  protected Map<Class<?>, List<Class<?>>> getRequiredTypeConverters() {
    final HashMap<Class<?>, List<Class<?>>> _typeConvertersMap = new HashMap<Class<?>, List<Class<?>>>();
    _typeConvertersMap.put(ThreatDao.class, ThreatDao_Impl.getRequiredConverters());
    _typeConvertersMap.put(ScanHistoryDao.class, ScanHistoryDao_Impl.getRequiredConverters());
    return _typeConvertersMap;
  }

  @Override
  @NonNull
  public Set<Class<? extends AutoMigrationSpec>> getRequiredAutoMigrationSpecs() {
    final HashSet<Class<? extends AutoMigrationSpec>> _autoMigrationSpecsSet = new HashSet<Class<? extends AutoMigrationSpec>>();
    return _autoMigrationSpecsSet;
  }

  @Override
  @NonNull
  public List<Migration> getAutoMigrations(
      @NonNull final Map<Class<? extends AutoMigrationSpec>, AutoMigrationSpec> autoMigrationSpecs) {
    final List<Migration> _autoMigrations = new ArrayList<Migration>();
    return _autoMigrations;
  }

  @Override
  public ThreatDao threatDao() {
    if (_threatDao != null) {
      return _threatDao;
    } else {
      synchronized(this) {
        if(_threatDao == null) {
          _threatDao = new ThreatDao_Impl(this);
        }
        return _threatDao;
      }
    }
  }

  @Override
  public ScanHistoryDao scanHistoryDao() {
    if (_scanHistoryDao != null) {
      return _scanHistoryDao;
    } else {
      synchronized(this) {
        if(_scanHistoryDao == null) {
          _scanHistoryDao = new ScanHistoryDao_Impl(this);
        }
        return _scanHistoryDao;
      }
    }
  }
}
