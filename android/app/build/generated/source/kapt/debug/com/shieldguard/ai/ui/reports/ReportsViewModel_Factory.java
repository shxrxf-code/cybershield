package com.shieldguard.ai.ui.reports;

import dagger.internal.DaggerGenerated;
import dagger.internal.Factory;
import dagger.internal.QualifierMetadata;
import dagger.internal.ScopeMetadata;
import javax.annotation.processing.Generated;

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
public final class ReportsViewModel_Factory implements Factory<ReportsViewModel> {
  @Override
  public ReportsViewModel get() {
    return newInstance();
  }

  public static ReportsViewModel_Factory create() {
    return InstanceHolder.INSTANCE;
  }

  public static ReportsViewModel newInstance() {
    return new ReportsViewModel();
  }

  private static final class InstanceHolder {
    private static final ReportsViewModel_Factory INSTANCE = new ReportsViewModel_Factory();
  }
}
