using Downpour.Service;

// Scheduled automatic release of host isolation (registered by HostIsolationExecutor). Exactly one fixed switch,
// no other arguments accepted; it removes the isolation rules and exits without starting the service.
if (args is [TaskSchedulerIsolationRelease.ReleaseSwitch])
    return HostIsolationExecutor.ReleaseFromScheduledTask();

AppDomain.CurrentDomain.UnhandledException += (_, e) => { if (e.ExceptionObject is Exception ex) ServiceFileLoggerProvider.RecordCrash(ex); };

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "Downpour Security Monitor";
});
// One sensor failing on an unusual PC must not take every other sensor down with it (the .NET default stops the host).
builder.Services.Configure<HostOptions>(options => options.BackgroundServiceExceptionBehavior = BackgroundServiceExceptionBehavior.Ignore);
builder.Logging.AddProvider(new ServiceFileLoggerProvider(ServiceFileLoggerProvider.DefaultPath()));
builder.Services.AddSingleton<SystemSnapshotProvider>();
builder.Services.AddSingleton(provider => new DriverInventoryProvider(provider.GetRequiredService<FileSignatureChecker>()));
builder.Services.AddSingleton<DriverPackageInventoryProvider>();
builder.Services.AddSingleton<WindowsServiceInventoryProvider>();
builder.Services.AddSingleton<InstalledSoftwareInventoryProvider>();
builder.Services.AddSingleton<NetworkInventoryProvider>();
builder.Services.AddSingleton<SecurityEventProvider>();
builder.Services.AddSingleton<SysmonProvider>();
builder.Services.AddSingleton<SecurityEventSnapshotStore>();
builder.Services.AddSingleton<SysmonSnapshotStore>();
builder.Services.AddSingleton<SecurityEventPushStatus>();
builder.Services.AddSingleton<SecurityAlertRepository>(SecurityAlertRepository.CreateForCurrentUser());
builder.Services.AddSingleton<SecurityAlertSnapshotStore>();
builder.Services.AddSingleton(OperationJournal.CreateForCurrentUser());
builder.Services.AddSingleton<QuarantineManager>();
builder.Services.AddSingleton<DriverPackageBroker>();
builder.Services.AddSingleton<HardeningPostureProvider>();
builder.Services.AddSingleton<FirewallInventoryProvider>();
builder.Services.AddSingleton<FileSignatureChecker>();
builder.Services.AddSingleton(provider => PersistenceInventoryProvider.CreateForCurrentUser(provider.GetRequiredService<FileSignatureChecker>()));
builder.Services.AddSingleton<UsbInventoryProvider>();
builder.Services.AddSingleton<WirelessInventoryProvider>();
builder.Services.AddSingleton<RemoteAccessProvider>();
builder.Services.AddSingleton(DnsInventoryProvider.CreateForCurrentUser());
builder.Services.AddSingleton(SensorSettingsStore.CreateForCurrentUser());
builder.Services.AddSingleton(IntelKeyStore.CreateForCurrentUser());
builder.Services.AddSingleton(IntelResultStore.CreateForCurrentUser());
builder.Services.AddSingleton(QuarantineVault.CreateForCurrentUser());
builder.Services.AddSingleton<QuarantineExecutor>();
builder.Services.AddSingleton<ActionConsentStore>(_ => new ActionConsentStore());
builder.Services.AddSingleton(ActionAuditLog.CreateForCurrentUser());
builder.Services.AddSingleton<IActionCallerVerifier, ParentDesktopCallerVerifier>();
builder.Services.AddSingleton<QuarantineActionHandler>();
builder.Services.AddSingleton<ProcessTerminationExecutor>();
builder.Services.AddSingleton<ProcessTerminationActionHandler>();
builder.Services.AddSingleton<FirewallActionExecutor>();
builder.Services.AddSingleton<FirewallActionHandler>();
builder.Services.AddSingleton<IUsbDeviceBackend, WindowsUsbDeviceBackend>();
builder.Services.AddSingleton<UsbActionExecutor>();
builder.Services.AddSingleton<UsbActionHandler>();
builder.Services.AddSingleton<HostIsolationExecutor>();
builder.Services.AddSingleton<HostIsolationHandler>();
builder.Services.AddSingleton<AntiStalkerProvider>();
builder.Services.AddSingleton<IAuthenticodeVerifier, AuthenticodeVerifier>();
builder.Services.AddSingleton<IYaraScannerBackend>(provider => new YaraScannerHost(provider.GetRequiredService<ILogger<YaraScannerHost>>()));
builder.Services.AddSingleton(provider => new YaraScanCoordinator(provider.GetRequiredService<IYaraScannerBackend>(),
    provider.GetRequiredService<SecurityAlertRepository>(), provider.GetRequiredService<ILogger<YaraScanCoordinator>>(),
    provider.GetRequiredService<IAuthenticodeVerifier>()));
builder.Services.AddHostedService<SnapshotPipeWorker>();
builder.Services.AddHostedService<DriverInventoryPipeWorker>();
builder.Services.AddHostedService<DriverPackageInventoryPipeWorker>();
builder.Services.AddHostedService<WindowsServiceInventoryPipeWorker>();
builder.Services.AddHostedService<InstalledSoftwareInventoryPipeWorker>();
builder.Services.AddHostedService<NetworkInventoryPipeWorker>();
builder.Services.AddHostedService<SecurityEventMonitorService>();
builder.Services.AddHostedService<SecurityEventPushWorker>();
builder.Services.AddHostedService<SigmaAmsiPushWorker>();
builder.Services.AddHostedService<SysmonPushWorker>();
builder.Services.AddHostedService<SecurityEventPipeWorker>();
builder.Services.AddHostedService<SecurityAlertPipeWorker>();
builder.Services.AddHostedService<SecurityAlertControlPipeWorker>();
builder.Services.AddHostedService<OperationJournalStartupWorker>();
builder.Services.AddHostedService<ActionBrokerPipeWorker>();
builder.Services.AddHostedService<DriverPackageBrokerPipeWorker>();
builder.Services.AddHostedService<HardeningPosturePipeWorker>();
builder.Services.AddHostedService<FirewallInventoryPipeWorker>();
builder.Services.AddHostedService<PersistenceInventoryPipeWorker>();
builder.Services.AddHostedService<UsbInventoryPipeWorker>();
builder.Services.AddHostedService<WirelessInventoryPipeWorker>();
builder.Services.AddHostedService<DnsInventoryPipeWorker>();
builder.Services.AddHostedService<SecurityFindingBridgeWorker>();
builder.Services.AddHostedService<RemoteAccessPipeWorker>();
builder.Services.AddHostedService<SensorSettingsPipeWorker>();
builder.Services.AddHostedService<IntelLookupWorker>();
builder.Services.AddHostedService<IntelPipeWorker>();
builder.Services.AddHostedService<QuarantineActionPipeWorker>();
builder.Services.AddHostedService<ProcessTerminationActionPipeWorker>();
builder.Services.AddHostedService<FirewallActionPipeWorker>();
builder.Services.AddHostedService<UsbActionPipeWorker>();
builder.Services.AddHostedService<HostIsolationPipeWorker>();
builder.Services.AddHostedService<AntiStalkerMonitor>();
builder.Services.AddSingleton<AudioShieldProvider>();
builder.Services.AddHostedService<AudioShieldMonitor>();
builder.Services.AddHostedService<AuditIntegrityMonitor>();
builder.Services.AddHostedService<HiddenProcessMonitor>();
builder.Services.AddHostedService<DeviceInventoryService>();
builder.Services.AddHostedService<LocalLearningWorker>();
builder.Services.AddSingleton<ThreatDatabaseService>();
builder.Services.AddHostedService(provider => provider.GetRequiredService<ThreatDatabaseService>());
builder.Services.AddHostedService<YaraScanPipeWorker>();

var host = builder.Build();
host.Run();
return 0;
