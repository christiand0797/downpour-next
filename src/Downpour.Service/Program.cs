using Downpour.Service;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "Downpour Security Monitor";
});
builder.Services.AddSingleton<SystemSnapshotProvider>();
builder.Services.AddSingleton<DriverInventoryProvider>();
builder.Services.AddSingleton<NetworkInventoryProvider>();
builder.Services.AddSingleton<SecurityEventProvider>();
builder.Services.AddSingleton<SecurityEventSnapshotStore>();
builder.Services.AddSingleton(OperationJournal.CreateForCurrentUser());
builder.Services.AddHostedService<SnapshotPipeWorker>();
builder.Services.AddHostedService<DriverInventoryPipeWorker>();
builder.Services.AddHostedService<NetworkInventoryPipeWorker>();
builder.Services.AddHostedService<SecurityEventMonitorService>();
builder.Services.AddHostedService<SecurityEventPipeWorker>();
builder.Services.AddHostedService<OperationJournalStartupWorker>();

var host = builder.Build();
host.Run();
