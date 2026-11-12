package com.shieldguard.ai.di;

import com.shieldguard.ai.data.local.ShieldGuardDatabase;
import com.shieldguard.ai.data.local.dao.ThreatDao;
import dagger.internal.DaggerGenerated;
import dagger.internal.Factory;
import dagger.internal.Preconditions;
import dagger.internal.QualifierMetadata;
import dagger.internal.ScopeMetadata;
import javax.annotation.processing.Generated;
import javax.inject.Provider;

@ScopeMetadata
@QualifierMetadata
@DaggerGenerated
@Generated(
    value = "dagger.internal.codegen.ComponentProcessor",
    comments = "https://dagger.dev"
)
@SuppressWarnings({
    "unchecked",
    "rawtypes",
    "KotlinInternal",
    "KotlinInternalInJava",
    "cast"
})
public final class DatabaseModule_ProvideThreatDaoFactory implements Factory<ThreatDao> {
  private final Provider<ShieldGuardDatabase> databaseProvider;

  public DatabaseModule_ProvideThreatDaoFactory(Provider<ShieldGuardDatabase> databaseProvider) {
    this.databaseProvider = databaseProvider;
  }

  @Override
  public ThreatDao get() {
    return provideThreatDao(databaseProvider.get());
  }

  public static DatabaseModule_ProvideThreatDaoFactory create(
      Provider<ShieldGuardDatabase> databaseProvider) {
    return new DatabaseModule_ProvideThreatDaoFactory(databaseProvider);
  }

  public static ThreatDao provideThreatDao(ShieldGuardDatabase database) {
    return Preconditions.checkNotNullFromProvides(DatabaseModule.INSTANCE.provideThreatDao(database));
  }
}
