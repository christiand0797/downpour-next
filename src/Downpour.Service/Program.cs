using Downpour.Service;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "Downpour Security Monitor";
});
builder.Services.AddSingleton<SystemSnapshotProvider>();
builder.Services.AddSingleton<DriverInventoryProvider>();
builder.Services.AddSingleton<NetworkInventoryProvider>();
builder.Services.AddHostedService<SnapshotPipeWorker>();
builder.Services.AddHostedService<DriverInventoryPipeWorker>();
builder.Services.AddHostedService<NetworkInventoryPipeWorker>();

var host = builder.Build();
host.Run();
