package com.shieldguard.ai.data.repository;

import com.shieldguard.ai.data.local.dao.ThreatDao;
import dagger.internal.DaggerGenerated;
import dagger.internal.Factory;
import dagger.internal.QualifierMetadata;
import dagger.internal.ScopeMetadata;
import javax.annotation.processing.Generated;
import javax.inject.Provider;

@ScopeMetadata("javax.inject.Singleton")
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
public final class ThreatRepositoryImpl_Factory implements Factory<ThreatRepositoryImpl> {
  private final Provider<ThreatDao> threatDaoProvider;

  public ThreatRepositoryImpl_Factory(Provider<ThreatDao> threatDaoProvider) {
    this.threatDaoProvider = threatDaoProvider;
  }

  @Override
  public ThreatRepositoryImpl get() {
    return newInstance(threatDaoProvider.get());
  }

  public static ThreatRepositoryImpl_Factory create(Provider<ThreatDao> threatDaoProvider) {
    return new ThreatRepositoryImpl_Factory(threatDaoProvider);
  }

  public static ThreatRepositoryImpl newInstance(ThreatDao threatDao) {
    return new ThreatRepositoryImpl(threatDao);
  }
}
