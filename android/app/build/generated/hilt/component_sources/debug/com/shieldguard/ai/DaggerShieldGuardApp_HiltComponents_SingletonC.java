package com.shieldguard.ai;

import android.app.Activity;
import android.app.Service;
import android.content.Context;
import android.view.View;
import androidx.fragment.app.Fragment;
import androidx.hilt.work.HiltWorkerFactory;
import androidx.hilt.work.WorkerAssistedFactory;
import androidx.hilt.work.WorkerFactoryModule_ProvideFactoryFactory;
import androidx.lifecycle.SavedStateHandle;
import androidx.lifecycle.ViewModel;
import androidx.work.ListenableWorker;
import androidx.work.WorkerParameters;
import com.shieldguard.ai.data.local.EncryptedPreferencesManager;
import com.shieldguard.ai.data.local.ShieldGuardDatabase;
import com.shieldguard.ai.data.local.dao.ScanHistoryDao;
import com.shieldguard.ai.data.local.dao.ThreatDao;
import com.shieldguard.ai.data.remote.AuthInterceptor;
import com.shieldguard.ai.data.remote.api.ShieldGuardApiService;
import com.shieldguard.ai.data.repository.DeviceSecurityRepositoryImpl;
import com.shieldguard.ai.data.repository.ScannerRepositoryImpl;
import com.shieldguard.ai.data.repository.ThreatRepositoryImpl;
import com.shieldguard.ai.di.DatabaseModule_ProvideDatabaseFactory;
import com.shieldguard.ai.di.DatabaseModule_ProvideScanHistoryDaoFactory;
import com.shieldguard.ai.di.DatabaseModule_ProvideThreatDaoFactory;
import com.shieldguard.ai.di.NetworkModule_ProvideApiServiceFactory;
import com.shieldguard.ai.di.NetworkModule_ProvideOkHttpClientFactory;
import com.shieldguard.ai.di.NetworkModule_ProvideRetrofitFactory;
import com.shieldguard.ai.domain.usecase.AuditDeviceSecurityUseCase;
import com.shieldguard.ai.domain.usecase.ProcessNotificationUseCase;
import com.shieldguard.ai.domain.usecase.ScanApkUseCase;
import com.shieldguard.ai.domain.usecase.ScanUrlUseCase;
import com.shieldguard.ai.scanner.ApkStaticScanner;
import com.shieldguard.ai.scanner.DeviceIntegrityAuditor;
import com.shieldguard.ai.scanner.DocumentSecurityScanner;
import com.shieldguard.ai.scanner.FullDeviceFileScanner;
import com.shieldguard.ai.scanner.LocalUrlThreatAnalyzer;
import com.shieldguard.ai.scanner.RootDetectionEngine;
import com.shieldguard.ai.service.NetworkTrafficMonitor;
import com.shieldguard.ai.service.NotificationMonitorHub;
import com.shieldguard.ai.service.NotificationMonitorService;
import com.shieldguard.ai.service.NotificationMonitorService_MembersInjector;
import com.shieldguard.ai.service.ScheduledScanWorker;
import com.shieldguard.ai.service.ScheduledScanWorker_AssistedFactory;
import com.shieldguard.ai.service.ShieldGuardVpnService;
import com.shieldguard.ai.service.ShieldGuardVpnService_MembersInjector;
import com.shieldguard.ai.ui.dashboard.DashboardViewModel;
import com.shieldguard.ai.ui.dashboard.DashboardViewModel_HiltModules;
import com.shieldguard.ai.ui.network.NetworkViewModel;
import com.shieldguard.ai.ui.network.NetworkViewModel_HiltModules;
import com.shieldguard.ai.ui.reports.ReportsViewModel;
import com.shieldguard.ai.ui.reports.ReportsViewModel_HiltModules;
import com.shieldguard.ai.ui.scanners.AppScannerViewModel;
import com.shieldguard.ai.ui.scanners.AppScannerViewModel_HiltModules;
import com.shieldguard.ai.ui.scanners.UrlScannerViewModel;
import com.shieldguard.ai.ui.scanners.UrlScannerViewModel_HiltModules;
import dagger.hilt.android.ActivityRetainedLifecycle;
import dagger.hilt.android.ViewModelLifecycle;
import dagger.hilt.android.internal.builders.ActivityComponentBuilder;
import dagger.hilt.android.internal.builders.ActivityRetainedComponentBuilder;
import dagger.hilt.android.internal.builders.FragmentComponentBuilder;
import dagger.hilt.android.internal.builders.ServiceComponentBuilder;
import dagger.hilt.android.internal.builders.ViewComponentBuilder;
import dagger.hilt.android.internal.builders.ViewModelComponentBuilder;
import dagger.hilt.android.internal.builders.ViewWithFragmentComponentBuilder;
import dagger.hilt.android.internal.lifecycle.DefaultViewModelFactories;
import dagger.hilt.android.internal.lifecycle.DefaultViewModelFactories_InternalFactoryFactory_Factory;
import dagger.hilt.android.internal.managers.ActivityRetainedComponentManager_LifecycleModule_ProvideActivityRetainedLifecycleFactory;
import dagger.hilt.android.internal.managers.SavedStateHandleHolder;
import dagger.hilt.android.internal.modules.ApplicationContextModule;
import dagger.hilt.android.internal.modules.ApplicationContextModule_ProvideContextFactory;
import dagger.internal.DaggerGenerated;
import dagger.internal.DoubleCheck;
import dagger.internal.IdentifierNameString;
import dagger.internal.KeepFieldType;
import dagger.internal.LazyClassKeyMap;
import dagger.internal.MapBuilder;
import dagger.internal.Preconditions;
import dagger.internal.Provider;
import dagger.internal.SingleCheck;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import javax.annotation.processing.Generated;
import okhttp3.OkHttpClient;
import retrofit2.Retrofit;

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
public final class DaggerShieldGuardApp_HiltComponents_SingletonC {
  private DaggerShieldGuardApp_HiltComponents_SingletonC() {
  }

  public static Builder builder() {
    return new Builder();
  }

  public static final class Builder {
    private ApplicationContextModule applicationContextModule;

    private Builder() {
    }

    public Builder applicationContextModule(ApplicationContextModule applicationContextModule) {
      this.applicationContextModule = Preconditions.checkNotNull(applicationContextModule);
      return this;
    }

    public ShieldGuardApp_HiltComponents.SingletonC build() {
      Preconditions.checkBuilderRequirement(applicationContextModule, ApplicationContextModule.class);
      return new SingletonCImpl(applicationContextModule);
    }
  }

  private static final class ActivityRetainedCBuilder implements ShieldGuardApp_HiltComponents.ActivityRetainedC.Builder {
    private final SingletonCImpl singletonCImpl;

    private SavedStateHandleHolder savedStateHandleHolder;

    private ActivityRetainedCBuilder(SingletonCImpl singletonCImpl) {
      this.singletonCImpl = singletonCImpl;
    }

    @Override
    public ActivityRetainedCBuilder savedStateHandleHolder(
        SavedStateHandleHolder savedStateHandleHolder) {
      this.savedStateHandleHolder = Preconditions.checkNotNull(savedStateHandleHolder);
      return this;
    }

    @Override
    public ShieldGuardApp_HiltComponents.ActivityRetainedC build() {
      Preconditions.checkBuilderRequirement(savedStateHandleHolder, SavedStateHandleHolder.class);
      return new ActivityRetainedCImpl(singletonCImpl, savedStateHandleHolder);
    }
  }

  private static final class ActivityCBuilder implements ShieldGuardApp_HiltComponents.ActivityC.Builder {
    private final SingletonCImpl singletonCImpl;

    private final ActivityRetainedCImpl activityRetainedCImpl;

    private Activity activity;

    private ActivityCBuilder(SingletonCImpl singletonCImpl,
        ActivityRetainedCImpl activityRetainedCImpl) {
      this.singletonCImpl = singletonCImpl;
      this.activityRetainedCImpl = activityRetainedCImpl;
    }

    @Override
    public ActivityCBuilder activity(Activity activity) {
      this.activity = Preconditions.checkNotNull(activity);
      return this;
    }

    @Override
    public ShieldGuardApp_HiltComponents.ActivityC build() {
      Preconditions.checkBuilderRequirement(activity, Activity.class);
      return new ActivityCImpl(singletonCImpl, activityRetainedCImpl, activity);
    }
  }

  private static final class FragmentCBuilder implements ShieldGuardApp_HiltComponents.FragmentC.Builder {
    private final SingletonCImpl singletonCImpl;

    private final ActivityRetainedCImpl activityRetainedCImpl;

    private final ActivityCImpl activityCImpl;

    private Fragment fragment;

    private FragmentCBuilder(SingletonCImpl singletonCImpl,
        ActivityRetainedCImpl activityRetainedCImpl, ActivityCImpl activityCImpl) {
      this.singletonCImpl = singletonCImpl;
      this.activityRetainedCImpl = activityRetainedCImpl;
      this.activityCImpl = activityCImpl;
    }

    @Override
    public FragmentCBuilder fragment(Fragment fragment) {
      this.fragment = Preconditions.checkNotNull(fragment);
      return this;
    }

    @Override
    public ShieldGuardApp_HiltComponents.FragmentC build() {
      Preconditions.checkBuilderRequirement(fragment, Fragment.class);
      return new FragmentCImpl(singletonCImpl, activityRetainedCImpl, activityCImpl, fragment);
    }
  }

  private static final class ViewWithFragmentCBuilder implements ShieldGuardApp_HiltComponents.ViewWithFragmentC.Builder {
    private final SingletonCImpl singletonCImpl;

    private final ActivityRetainedCImpl activityRetainedCImpl;

    private final ActivityCImpl activityCImpl;

    private final FragmentCImpl fragmentCImpl;

    private View view;

    private ViewWithFragmentCBuilder(SingletonCImpl singletonCImpl,
        ActivityRetainedCImpl activityRetainedCImpl, ActivityCImpl activityCImpl,
        FragmentCImpl fragmentCImpl) {
      this.singletonCImpl = singletonCImpl;
      this.activityRetainedCImpl = activityRetainedCImpl;
      this.activityCImpl = activityCImpl;
      this.fragmentCImpl = fragmentCImpl;
    }

    @Override
    public ViewWithFragmentCBuilder view(View view) {
      this.view = Preconditions.checkNotNull(view);
      return this;
    }

    @Override
    public ShieldGuardApp_HiltComponents.ViewWithFragmentC build() {
      Preconditions.checkBuilderRequirement(view, View.class);
      return new ViewWithFragmentCImpl(singletonCImpl, activityRetainedCImpl, activityCImpl, fragmentCImpl, view);
    }
  }

  private static final class ViewCBuilder implements ShieldGuardApp_HiltComponents.ViewC.Builder {
    private final SingletonCImpl singletonCImpl;

    private final ActivityRetainedCImpl activityRetainedCImpl;

    private final ActivityCImpl activityCImpl;

    private View view;

    private ViewCBuilder(SingletonCImpl singletonCImpl, ActivityRetainedCImpl activityRetainedCImpl,
        ActivityCImpl activityCImpl) {
      this.singletonCImpl = singletonCImpl;
      this.activityRetainedCImpl = activityRetainedCImpl;
      this.activityCImpl = activityCImpl;
    }

    @Override
    public ViewCBuilder view(View view) {
      this.view = Preconditions.checkNotNull(view);
      return this;
    }

    @Override
    public ShieldGuardApp_HiltComponents.ViewC build() {
      Preconditions.checkBuilderRequirement(view, View.class);
      return new ViewCImpl(singletonCImpl, activityRetainedCImpl, activityCImpl, view);
    }
  }

  private static final class ViewModelCBuilder implements ShieldGuardApp_HiltComponents.ViewModelC.Builder {
    private final SingletonCImpl singletonCImpl;

    private final ActivityRetainedCImpl activityRetainedCImpl;

    private SavedStateHandle savedStateHandle;

    private ViewModelLifecycle viewModelLifecycle;

    private ViewModelCBuilder(SingletonCImpl singletonCImpl,
        ActivityRetainedCImpl activityRetainedCImpl) {
      this.singletonCImpl = singletonCImpl;
      this.activityRetainedCImpl = activityRetainedCImpl;
    }

    @Override
    public ViewModelCBuilder savedStateHandle(SavedStateHandle handle) {
      this.savedStateHandle = Preconditions.checkNotNull(handle);
      return this;
    }

    @Override
    public ViewModelCBuilder viewModelLifecycle(ViewModelLifecycle viewModelLifecycle) {
      this.viewModelLifecycle = Preconditions.checkNotNull(viewModelLifecycle);
      return this;
    }

    @Override
    public ShieldGuardApp_HiltComponents.ViewModelC build() {
      Preconditions.checkBuilderRequirement(savedStateHandle, SavedStateHandle.class);
      Preconditions.checkBuilderRequirement(viewModelLifecycle, ViewModelLifecycle.class);
      return new ViewModelCImpl(singletonCImpl, activityRetainedCImpl, savedStateHandle, viewModelLifecycle);
    }
  }

  private static final class ServiceCBuilder implements ShieldGuardApp_HiltComponents.ServiceC.Builder {
    private final SingletonCImpl singletonCImpl;

    private Service service;

    private ServiceCBuilder(SingletonCImpl singletonCImpl) {
      this.singletonCImpl = singletonCImpl;
    }

    @Override
    public ServiceCBuilder service(Service service) {
      this.service = Preconditions.checkNotNull(service);
      return this;
    }

    @Override
    public ShieldGuardApp_HiltComponents.ServiceC build() {
      Preconditions.checkBuilderRequirement(service, Service.class);
      return new ServiceCImpl(singletonCImpl, service);
    }
  }

  private static final class ViewWithFragmentCImpl extends ShieldGuardApp_HiltComponents.ViewWithFragmentC {
    private final SingletonCImpl singletonCImpl;

    private final ActivityRetainedCImpl activityRetainedCImpl;

    private final ActivityCImpl activityCImpl;

    private final FragmentCImpl fragmentCImpl;

    private final ViewWithFragmentCImpl viewWithFragmentCImpl = this;

    private ViewWithFragmentCImpl(SingletonCImpl singletonCImpl,
        ActivityRetainedCImpl activityRetainedCImpl, ActivityCImpl activityCImpl,
        FragmentCImpl fragmentCImpl, View viewParam) {
      this.singletonCImpl = singletonCImpl;
      this.activityRetainedCImpl = activityRetainedCImpl;
      this.activityCImpl = activityCImpl;
      this.fragmentCImpl = fragmentCImpl;


    }
  }

  private static final class FragmentCImpl extends ShieldGuardApp_HiltComponents.FragmentC {
    private final SingletonCImpl singletonCImpl;

    private final ActivityRetainedCImpl activityRetainedCImpl;

    private final ActivityCImpl activityCImpl;

    private final FragmentCImpl fragmentCImpl = this;

    private FragmentCImpl(SingletonCImpl singletonCImpl,
        ActivityRetainedCImpl activityRetainedCImpl, ActivityCImpl activityCImpl,
        Fragment fragmentParam) {
      this.singletonCImpl = singletonCImpl;
      this.activityRetainedCImpl = activityRetainedCImpl;
      this.activityCImpl = activityCImpl;


    }

    @Override
    public DefaultViewModelFactories.InternalFactoryFactory getHiltInternalFactoryFactory() {
      return activityCImpl.getHiltInternalFactoryFactory();
    }

    @Override
    public ViewWithFragmentComponentBuilder viewWithFragmentComponentBuilder() {
      return new ViewWithFragmentCBuilder(singletonCImpl, activityRetainedCImpl, activityCImpl, fragmentCImpl);
    }
  }

  private static final class ViewCImpl extends ShieldGuardApp_HiltComponents.ViewC {
    private final SingletonCImpl singletonCImpl;

    private final ActivityRetainedCImpl activityRetainedCImpl;

    private final ActivityCImpl activityCImpl;

    private final ViewCImpl viewCImpl = this;

    private ViewCImpl(SingletonCImpl singletonCImpl, ActivityRetainedCImpl activityRetainedCImpl,
        ActivityCImpl activityCImpl, View viewParam) {
      this.singletonCImpl = singletonCImpl;
      this.activityRetainedCImpl = activityRetainedCImpl;
      this.activityCImpl = activityCImpl;


    }
  }

  private static final class ActivityCImpl extends ShieldGuardApp_HiltComponents.ActivityC {
    private final SingletonCImpl singletonCImpl;

    private final ActivityRetainedCImpl activityRetainedCImpl;

    private final ActivityCImpl activityCImpl = this;

    private ActivityCImpl(SingletonCImpl singletonCImpl,
        ActivityRetainedCImpl activityRetainedCImpl, Activity activityParam) {
      this.singletonCImpl = singletonCImpl;
      this.activityRetainedCImpl = activityRetainedCImpl;


    }

    @Override
    public void injectMainActivity(MainActivity mainActivity) {
    }

    @Override
    public DefaultViewModelFactories.InternalFactoryFactory getHiltInternalFactoryFactory() {
      return DefaultViewModelFactories_InternalFactoryFactory_Factory.newInstance(getViewModelKeys(), new ViewModelCBuilder(singletonCImpl, activityRetainedCImpl));
    }

    @Override
    public Map<Class<?>, Boolean> getViewModelKeys() {
      return LazyClassKeyMap.<Boolean>of(MapBuilder.<String, Boolean>newMapBuilder(5).put(LazyClassKeyProvider.com_shieldguard_ai_ui_scanners_AppScannerViewModel, AppScannerViewModel_HiltModules.KeyModule.provide()).put(LazyClassKeyProvider.com_shieldguard_ai_ui_dashboard_DashboardViewModel, DashboardViewModel_HiltModules.KeyModule.provide()).put(LazyClassKeyProvider.com_shieldguard_ai_ui_network_NetworkViewModel, NetworkViewModel_HiltModules.KeyModule.provide()).put(LazyClassKeyProvider.com_shieldguard_ai_ui_reports_ReportsViewModel, ReportsViewModel_HiltModules.KeyModule.provide()).put(LazyClassKeyProvider.com_shieldguard_ai_ui_scanners_UrlScannerViewModel, UrlScannerViewModel_HiltModules.KeyModule.provide()).build());
    }

    @Override
    public ViewModelComponentBuilder getViewModelComponentBuilder() {
      return new ViewModelCBuilder(singletonCImpl, activityRetainedCImpl);
    }

    @Override
    public FragmentComponentBuilder fragmentComponentBuilder() {
      return new FragmentCBuilder(singletonCImpl, activityRetainedCImpl, activityCImpl);
    }

    @Override
    public ViewComponentBuilder viewComponentBuilder() {
      return new ViewCBuilder(singletonCImpl, activityRetainedCImpl, activityCImpl);
    }

    @IdentifierNameString
    private static final class LazyClassKeyProvider {
      static String com_shieldguard_ai_ui_scanners_AppScannerViewModel = "com.shieldguard.ai.ui.scanners.AppScannerViewModel";

      static String com_shieldguard_ai_ui_network_NetworkViewModel = "com.shieldguard.ai.ui.network.NetworkViewModel";

      static String com_shieldguard_ai_ui_dashboard_DashboardViewModel = "com.shieldguard.ai.ui.dashboard.DashboardViewModel";

      static String com_shieldguard_ai_ui_reports_ReportsViewModel = "com.shieldguard.ai.ui.reports.ReportsViewModel";

      static String com_shieldguard_ai_ui_scanners_UrlScannerViewModel = "com.shieldguard.ai.ui.scanners.UrlScannerViewModel";

      @KeepFieldType
      AppScannerViewModel com_shieldguard_ai_ui_scanners_AppScannerViewModel2;

      @KeepFieldType
      NetworkViewModel com_shieldguard_ai_ui_network_NetworkViewModel2;

      @KeepFieldType
      DashboardViewModel com_shieldguard_ai_ui_dashboard_DashboardViewModel2;

      @KeepFieldType
      ReportsViewModel com_shieldguard_ai_ui_reports_ReportsViewModel2;

      @KeepFieldType
      UrlScannerViewModel com_shieldguard_ai_ui_scanners_UrlScannerViewModel2;
    }
  }

  private static final class ViewModelCImpl extends ShieldGuardApp_HiltComponents.ViewModelC {
    private final SingletonCImpl singletonCImpl;

    private final ActivityRetainedCImpl activityRetainedCImpl;

    private final ViewModelCImpl viewModelCImpl = this;

    private Provider<AppScannerViewModel> appScannerViewModelProvider;

    private Provider<DashboardViewModel> dashboardViewModelProvider;

    private Provider<NetworkViewModel> networkViewModelProvider;

    private Provider<ReportsViewModel> reportsViewModelProvider;

    private Provider<UrlScannerViewModel> urlScannerViewModelProvider;

    private ViewModelCImpl(SingletonCImpl singletonCImpl,
        ActivityRetainedCImpl activityRetainedCImpl, SavedStateHandle savedStateHandleParam,
        ViewModelLifecycle viewModelLifecycleParam) {
      this.singletonCImpl = singletonCImpl;
      this.activityRetainedCImpl = activityRetainedCImpl;

      initialize(savedStateHandleParam, viewModelLifecycleParam);

    }

    private ScanApkUseCase scanApkUseCase() {
      return new ScanApkUseCase(singletonCImpl.scannerRepositoryImplProvider.get(), singletonCImpl.threatRepositoryImplProvider.get());
    }

    private AuditDeviceSecurityUseCase auditDeviceSecurityUseCase() {
      return new AuditDeviceSecurityUseCase(singletonCImpl.deviceSecurityRepositoryImplProvider.get());
    }

    private ScanUrlUseCase scanUrlUseCase() {
      return new ScanUrlUseCase(singletonCImpl.scannerRepositoryImplProvider.get(), singletonCImpl.threatRepositoryImplProvider.get());
    }

    @SuppressWarnings("unchecked")
    private void initialize(final SavedStateHandle savedStateHandleParam,
        final ViewModelLifecycle viewModelLifecycleParam) {
      this.appScannerViewModelProvider = new SwitchingProvider<>(singletonCImpl, activityRetainedCImpl, viewModelCImpl, 0);
      this.dashboardViewModelProvider = new SwitchingProvider<>(singletonCImpl, activityRetainedCImpl, viewModelCImpl, 1);
      this.networkViewModelProvider = new SwitchingProvider<>(singletonCImpl, activityRetainedCImpl, viewModelCImpl, 2);
      this.reportsViewModelProvider = new SwitchingProvider<>(singletonCImpl, activityRetainedCImpl, viewModelCImpl, 3);
      this.urlScannerViewModelProvider = new SwitchingProvider<>(singletonCImpl, activityRetainedCImpl, viewModelCImpl, 4);
    }

    @Override
    public Map<Class<?>, javax.inject.Provider<ViewModel>> getHiltViewModelMap() {
      return LazyClassKeyMap.<javax.inject.Provider<ViewModel>>of(MapBuilder.<String, javax.inject.Provider<ViewModel>>newMapBuilder(5).put(LazyClassKeyProvider.com_shieldguard_ai_ui_scanners_AppScannerViewModel, ((Provider) appScannerViewModelProvider)).put(LazyClassKeyProvider.com_shieldguard_ai_ui_dashboard_DashboardViewModel, ((Provider) dashboardViewModelProvider)).put(LazyClassKeyProvider.com_shieldguard_ai_ui_network_NetworkViewModel, ((Provider) networkViewModelProvider)).put(LazyClassKeyProvider.com_shieldguard_ai_ui_reports_ReportsViewModel, ((Provider) reportsViewModelProvider)).put(LazyClassKeyProvider.com_shieldguard_ai_ui_scanners_UrlScannerViewModel, ((Provider) urlScannerViewModelProvider)).build());
    }

    @Override
    public Map<Class<?>, Object> getHiltViewModelAssistedMap() {
      return Collections.<Class<?>, Object>emptyMap();
    }

    @IdentifierNameString
    private static final class LazyClassKeyProvider {
      static String com_shieldguard_ai_ui_reports_ReportsViewModel = "com.shieldguard.ai.ui.reports.ReportsViewModel";

      static String com_shieldguard_ai_ui_dashboard_DashboardViewModel = "com.shieldguard.ai.ui.dashboard.DashboardViewModel";

      static String com_shieldguard_ai_ui_network_NetworkViewModel = "com.shieldguard.ai.ui.network.NetworkViewModel";

      static String com_shieldguard_ai_ui_scanners_UrlScannerViewModel = "com.shieldguard.ai.ui.scanners.UrlScannerViewModel";

      static String com_shieldguard_ai_ui_scanners_AppScannerViewModel = "com.shieldguard.ai.ui.scanners.AppScannerViewModel";

      @KeepFieldType
      ReportsViewModel com_shieldguard_ai_ui_reports_ReportsViewModel2;

      @KeepFieldType
      DashboardViewModel com_shieldguard_ai_ui_dashboard_DashboardViewModel2;

      @KeepFieldType
      NetworkViewModel com_shieldguard_ai_ui_network_NetworkViewModel2;

      @KeepFieldType
      UrlScannerViewModel com_shieldguard_ai_ui_scanners_UrlScannerViewModel2;

      @KeepFieldType
      AppScannerViewModel com_shieldguard_ai_ui_scanners_AppScannerViewModel2;
    }

    private static final class SwitchingProvider<T> implements Provider<T> {
      private final SingletonCImpl singletonCImpl;

      private final ActivityRetainedCImpl activityRetainedCImpl;

      private final ViewModelCImpl viewModelCImpl;

      private final int id;

      SwitchingProvider(SingletonCImpl singletonCImpl, ActivityRetainedCImpl activityRetainedCImpl,
          ViewModelCImpl viewModelCImpl, int id) {
        this.singletonCImpl = singletonCImpl;
        this.activityRetainedCImpl = activityRetainedCImpl;
        this.viewModelCImpl = viewModelCImpl;
        this.id = id;
      }

      @SuppressWarnings("unchecked")
      @Override
      public T get() {
        switch (id) {
          case 0: // com.shieldguard.ai.ui.scanners.AppScannerViewModel 
          return (T) new AppScannerViewModel(singletonCImpl.apkStaticScannerProvider.get(), viewModelCImpl.scanApkUseCase(), singletonCImpl.threatRepositoryImplProvider.get());

          case 1: // com.shieldguard.ai.ui.dashboard.DashboardViewModel 
          return (T) new DashboardViewModel(ApplicationContextModule_ProvideContextFactory.provideContext(singletonCImpl.applicationContextModule), singletonCImpl.deviceSecurityRepositoryImplProvider.get(), singletonCImpl.threatRepositoryImplProvider.get(), singletonCImpl.scannerRepositoryImplProvider.get(), viewModelCImpl.auditDeviceSecurityUseCase(), singletonCImpl.apkStaticScannerProvider.get(), singletonCImpl.fullDeviceFileScannerProvider.get(), singletonCImpl.networkTrafficMonitorProvider.get(), singletonCImpl.notificationMonitorHubProvider.get());

          case 2: // com.shieldguard.ai.ui.network.NetworkViewModel 
          return (T) new NetworkViewModel(singletonCImpl.networkTrafficMonitorProvider.get(), singletonCImpl.encryptedPreferencesManagerProvider.get());

          case 3: // com.shieldguard.ai.ui.reports.ReportsViewModel 
          return (T) new ReportsViewModel();

          case 4: // com.shieldguard.ai.ui.scanners.UrlScannerViewModel 
          return (T) new UrlScannerViewModel(viewModelCImpl.scanUrlUseCase());

          default: throw new AssertionError(id);
        }
      }
    }
  }

  private static final class ActivityRetainedCImpl extends ShieldGuardApp_HiltComponents.ActivityRetainedC {
    private final SingletonCImpl singletonCImpl;

    private final ActivityRetainedCImpl activityRetainedCImpl = this;

    private Provider<ActivityRetainedLifecycle> provideActivityRetainedLifecycleProvider;

    private ActivityRetainedCImpl(SingletonCImpl singletonCImpl,
        SavedStateHandleHolder savedStateHandleHolderParam) {
      this.singletonCImpl = singletonCImpl;

      initialize(savedStateHandleHolderParam);

    }

    @SuppressWarnings("unchecked")
    private void initialize(final SavedStateHandleHolder savedStateHandleHolderParam) {
      this.provideActivityRetainedLifecycleProvider = DoubleCheck.provider(new SwitchingProvider<ActivityRetainedLifecycle>(singletonCImpl, activityRetainedCImpl, 0));
    }

    @Override
    public ActivityComponentBuilder activityComponentBuilder() {
      return new ActivityCBuilder(singletonCImpl, activityRetainedCImpl);
    }

    @Override
    public ActivityRetainedLifecycle getActivityRetainedLifecycle() {
      return provideActivityRetainedLifecycleProvider.get();
    }

    private static final class SwitchingProvider<T> implements Provider<T> {
      private final SingletonCImpl singletonCImpl;

      private final ActivityRetainedCImpl activityRetainedCImpl;

      private final int id;

      SwitchingProvider(SingletonCImpl singletonCImpl, ActivityRetainedCImpl activityRetainedCImpl,
          int id) {
        this.singletonCImpl = singletonCImpl;
        this.activityRetainedCImpl = activityRetainedCImpl;
        this.id = id;
      }

      @SuppressWarnings("unchecked")
      @Override
      public T get() {
        switch (id) {
          case 0: // dagger.hilt.android.ActivityRetainedLifecycle 
          return (T) ActivityRetainedComponentManager_LifecycleModule_ProvideActivityRetainedLifecycleFactory.provideActivityRetainedLifecycle();

          default: throw new AssertionError(id);
        }
      }
    }
  }

  private static final class ServiceCImpl extends ShieldGuardApp_HiltComponents.ServiceC {
    private final SingletonCImpl singletonCImpl;

    private final ServiceCImpl serviceCImpl = this;

    private ServiceCImpl(SingletonCImpl singletonCImpl, Service serviceParam) {
      this.singletonCImpl = singletonCImpl;


    }

    private ScanUrlUseCase scanUrlUseCase() {
      return new ScanUrlUseCase(singletonCImpl.scannerRepositoryImplProvider.get(), singletonCImpl.threatRepositoryImplProvider.get());
    }

    private ProcessNotificationUseCase processNotificationUseCase() {
      return new ProcessNotificationUseCase(singletonCImpl.threatRepositoryImplProvider.get(), scanUrlUseCase(), singletonCImpl.localUrlThreatAnalyzerProvider.get(), singletonCImpl.notificationMonitorHubProvider.get());
    }

    @Override
    public void injectNotificationMonitorService(
        NotificationMonitorService notificationMonitorService) {
      injectNotificationMonitorService2(notificationMonitorService);
    }

    @Override
    public void injectShieldGuardVpnService(ShieldGuardVpnService shieldGuardVpnService) {
      injectShieldGuardVpnService2(shieldGuardVpnService);
    }

    private NotificationMonitorService injectNotificationMonitorService2(
        NotificationMonitorService instance) {
      NotificationMonitorService_MembersInjector.injectProcessNotificationUseCase(instance, processNotificationUseCase());
      NotificationMonitorService_MembersInjector.injectPreferencesManager(instance, singletonCImpl.encryptedPreferencesManagerProvider.get());
      return instance;
    }

    private ShieldGuardVpnService injectShieldGuardVpnService2(ShieldGuardVpnService instance) {
      ShieldGuardVpnService_MembersInjector.injectNetworkTrafficMonitor(instance, singletonCImpl.networkTrafficMonitorProvider.get());
      ShieldGuardVpnService_MembersInjector.injectThreatRepository(instance, singletonCImpl.threatRepositoryImplProvider.get());
      ShieldGuardVpnService_MembersInjector.injectPreferencesManager(instance, singletonCImpl.encryptedPreferencesManagerProvider.get());
      return instance;
    }
  }

  private static final class SingletonCImpl extends ShieldGuardApp_HiltComponents.SingletonC {
    private final ApplicationContextModule applicationContextModule;

    private final SingletonCImpl singletonCImpl = this;

    private Provider<RootDetectionEngine> rootDetectionEngineProvider;

    private Provider<DeviceIntegrityAuditor> deviceIntegrityAuditorProvider;

    private Provider<ApkStaticScanner> apkStaticScannerProvider;

    private Provider<EncryptedPreferencesManager> encryptedPreferencesManagerProvider;

    private Provider<AuthInterceptor> authInterceptorProvider;

    private Provider<OkHttpClient> provideOkHttpClientProvider;

    private Provider<Retrofit> provideRetrofitProvider;

    private Provider<ShieldGuardApiService> provideApiServiceProvider;

    private Provider<DocumentSecurityScanner> documentSecurityScannerProvider;

    private Provider<NetworkTrafficMonitor> networkTrafficMonitorProvider;

    private Provider<LocalUrlThreatAnalyzer> localUrlThreatAnalyzerProvider;

    private Provider<ShieldGuardDatabase> provideDatabaseProvider;

    private Provider<ScannerRepositoryImpl> scannerRepositoryImplProvider;

    private Provider<ScheduledScanWorker_AssistedFactory> scheduledScanWorker_AssistedFactoryProvider;

    private Provider<ThreatRepositoryImpl> threatRepositoryImplProvider;

    private Provider<DeviceSecurityRepositoryImpl> deviceSecurityRepositoryImplProvider;

    private Provider<FullDeviceFileScanner> fullDeviceFileScannerProvider;

    private Provider<NotificationMonitorHub> notificationMonitorHubProvider;

    private SingletonCImpl(ApplicationContextModule applicationContextModuleParam) {
      this.applicationContextModule = applicationContextModuleParam;
      initialize(applicationContextModuleParam);

    }

    private ScanHistoryDao scanHistoryDao() {
      return DatabaseModule_ProvideScanHistoryDaoFactory.provideScanHistoryDao(provideDatabaseProvider.get());
    }

    private Map<String, javax.inject.Provider<WorkerAssistedFactory<? extends ListenableWorker>>> mapOfStringAndProviderOfWorkerAssistedFactoryOf(
        ) {
      return Collections.<String, javax.inject.Provider<WorkerAssistedFactory<? extends ListenableWorker>>>singletonMap("com.shieldguard.ai.service.ScheduledScanWorker", ((Provider) scheduledScanWorker_AssistedFactoryProvider));
    }

    private HiltWorkerFactory hiltWorkerFactory() {
      return WorkerFactoryModule_ProvideFactoryFactory.provideFactory(mapOfStringAndProviderOfWorkerAssistedFactoryOf());
    }

    private ThreatDao threatDao() {
      return DatabaseModule_ProvideThreatDaoFactory.provideThreatDao(provideDatabaseProvider.get());
    }

    @SuppressWarnings("unchecked")
    private void initialize(final ApplicationContextModule applicationContextModuleParam) {
      this.rootDetectionEngineProvider = DoubleCheck.provider(new SwitchingProvider<RootDetectionEngine>(singletonCImpl, 2));
      this.deviceIntegrityAuditorProvider = DoubleCheck.provider(new SwitchingProvider<DeviceIntegrityAuditor>(singletonCImpl, 1));
      this.apkStaticScannerProvider = DoubleCheck.provider(new SwitchingProvider<ApkStaticScanner>(singletonCImpl, 3));
      this.encryptedPreferencesManagerProvider = DoubleCheck.provider(new SwitchingProvider<EncryptedPreferencesManager>(singletonCImpl, 9));
      this.authInterceptorProvider = DoubleCheck.provider(new SwitchingProvider<AuthInterceptor>(singletonCImpl, 8));
      this.provideOkHttpClientProvider = DoubleCheck.provider(new SwitchingProvider<OkHttpClient>(singletonCImpl, 7));
      this.provideRetrofitProvider = DoubleCheck.provider(new SwitchingProvider<Retrofit>(singletonCImpl, 6));
      this.provideApiServiceProvider = DoubleCheck.provider(new SwitchingProvider<ShieldGuardApiService>(singletonCImpl, 5));
      this.documentSecurityScannerProvider = DoubleCheck.provider(new SwitchingProvider<DocumentSecurityScanner>(singletonCImpl, 10));
      this.networkTrafficMonitorProvider = DoubleCheck.provider(new SwitchingProvider<NetworkTrafficMonitor>(singletonCImpl, 12));
      this.localUrlThreatAnalyzerProvider = DoubleCheck.provider(new SwitchingProvider<LocalUrlThreatAnalyzer>(singletonCImpl, 11));
      this.provideDatabaseProvider = DoubleCheck.provider(new SwitchingProvider<ShieldGuardDatabase>(singletonCImpl, 13));
      this.scannerRepositoryImplProvider = DoubleCheck.provider(new SwitchingProvider<ScannerRepositoryImpl>(singletonCImpl, 4));
      this.scheduledScanWorker_AssistedFactoryProvider = SingleCheck.provider(new SwitchingProvider<ScheduledScanWorker_AssistedFactory>(singletonCImpl, 0));
      this.threatRepositoryImplProvider = DoubleCheck.provider(new SwitchingProvider<ThreatRepositoryImpl>(singletonCImpl, 14));
      this.deviceSecurityRepositoryImplProvider = DoubleCheck.provider(new SwitchingProvider<DeviceSecurityRepositoryImpl>(singletonCImpl, 15));
      this.fullDeviceFileScannerProvider = DoubleCheck.provider(new SwitchingProvider<FullDeviceFileScanner>(singletonCImpl, 16));
      this.notificationMonitorHubProvider = DoubleCheck.provider(new SwitchingProvider<NotificationMonitorHub>(singletonCImpl, 17));
    }

    @Override
    public void injectShieldGuardApp(ShieldGuardApp shieldGuardApp) {
      injectShieldGuardApp2(shieldGuardApp);
    }

    @Override
    public Set<Boolean> getDisableFragmentGetContextFix() {
      return Collections.<Boolean>emptySet();
    }

    @Override
    public ActivityRetainedComponentBuilder retainedComponentBuilder() {
      return new ActivityRetainedCBuilder(singletonCImpl);
    }

    @Override
    public ServiceComponentBuilder serviceComponentBuilder() {
      return new ServiceCBuilder(singletonCImpl);
    }

    private ShieldGuardApp injectShieldGuardApp2(ShieldGuardApp instance) {
      ShieldGuardApp_MembersInjector.injectWorkerFactory(instance, hiltWorkerFactory());
      return instance;
    }

    private static final class SwitchingProvider<T> implements Provider<T> {
      private final SingletonCImpl singletonCImpl;

      private final int id;

      SwitchingProvider(SingletonCImpl singletonCImpl, int id) {
        this.singletonCImpl = singletonCImpl;
        this.id = id;
      }

      @SuppressWarnings("unchecked")
      @Override
      public T get() {
        switch (id) {
          case 0: // com.shieldguard.ai.service.ScheduledScanWorker_AssistedFactory 
          return (T) new ScheduledScanWorker_AssistedFactory() {
            @Override
            public ScheduledScanWorker create(Context appContext, WorkerParameters workerParams) {
              return new ScheduledScanWorker(appContext, workerParams, singletonCImpl.deviceIntegrityAuditorProvider.get(), singletonCImpl.apkStaticScannerProvider.get(), singletonCImpl.scannerRepositoryImplProvider.get(), singletonCImpl.encryptedPreferencesManagerProvider.get());
            }
          };

          case 1: // com.shieldguard.ai.scanner.DeviceIntegrityAuditor 
          return (T) new DeviceIntegrityAuditor(ApplicationContextModule_ProvideContextFactory.provideContext(singletonCImpl.applicationContextModule), singletonCImpl.rootDetectionEngineProvider.get());

          case 2: // com.shieldguard.ai.scanner.RootDetectionEngine 
          return (T) new RootDetectionEngine(ApplicationContextModule_ProvideContextFactory.provideContext(singletonCImpl.applicationContextModule));

          case 3: // com.shieldguard.ai.scanner.ApkStaticScanner 
          return (T) new ApkStaticScanner(ApplicationContextModule_ProvideContextFactory.provideContext(singletonCImpl.applicationContextModule));

          case 4: // com.shieldguard.ai.data.repository.ScannerRepositoryImpl 
          return (T) new ScannerRepositoryImpl(singletonCImpl.provideApiServiceProvider.get(), singletonCImpl.documentSecurityScannerProvider.get(), singletonCImpl.localUrlThreatAnalyzerProvider.get(), singletonCImpl.scanHistoryDao(), singletonCImpl.encryptedPreferencesManagerProvider.get());

          case 5: // com.shieldguard.ai.data.remote.api.ShieldGuardApiService 
          return (T) NetworkModule_ProvideApiServiceFactory.provideApiService(singletonCImpl.provideRetrofitProvider.get());

          case 6: // retrofit2.Retrofit 
          return (T) NetworkModule_ProvideRetrofitFactory.provideRetrofit(singletonCImpl.provideOkHttpClientProvider.get());

          case 7: // okhttp3.OkHttpClient 
          return (T) NetworkModule_ProvideOkHttpClientFactory.provideOkHttpClient(singletonCImpl.authInterceptorProvider.get());

          case 8: // com.shieldguard.ai.data.remote.AuthInterceptor 
          return (T) new AuthInterceptor(singletonCImpl.encryptedPreferencesManagerProvider.get());

          case 9: // com.shieldguard.ai.data.local.EncryptedPreferencesManager 
          return (T) new EncryptedPreferencesManager(ApplicationContextModule_ProvideContextFactory.provideContext(singletonCImpl.applicationContextModule));

          case 10: // com.shieldguard.ai.scanner.DocumentSecurityScanner 
          return (T) new DocumentSecurityScanner();

          case 11: // com.shieldguard.ai.scanner.LocalUrlThreatAnalyzer 
          return (T) new LocalUrlThreatAnalyzer(singletonCImpl.networkTrafficMonitorProvider.get());

          case 12: // com.shieldguard.ai.service.NetworkTrafficMonitor 
          return (T) new NetworkTrafficMonitor();

          case 13: // com.shieldguard.ai.data.local.ShieldGuardDatabase 
          return (T) DatabaseModule_ProvideDatabaseFactory.provideDatabase(ApplicationContextModule_ProvideContextFactory.provideContext(singletonCImpl.applicationContextModule));

          case 14: // com.shieldguard.ai.data.repository.ThreatRepositoryImpl 
          return (T) new ThreatRepositoryImpl(singletonCImpl.threatDao());

          case 15: // com.shieldguard.ai.data.repository.DeviceSecurityRepositoryImpl 
          return (T) new DeviceSecurityRepositoryImpl(singletonCImpl.deviceIntegrityAuditorProvider.get(), singletonCImpl.threatDao(), singletonCImpl.encryptedPreferencesManagerProvider.get());

          case 16: // com.shieldguard.ai.scanner.FullDeviceFileScanner 
          return (T) new FullDeviceFileScanner(ApplicationContextModule_ProvideContextFactory.provideContext(singletonCImpl.applicationContextModule), singletonCImpl.documentSecurityScannerProvider.get());

          case 17: // com.shieldguard.ai.service.NotificationMonitorHub 
          return (T) new NotificationMonitorHub();

          default: throw new AssertionError(id);
        }
      }
    }
  }
}
