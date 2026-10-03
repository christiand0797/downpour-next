using Downpour.Service;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "Downpour Security Monitor";
});
builder.Services.AddSingleton<SystemSnapshotProvider>();
builder.Services.AddHostedService<SnapshotPipeWorker>();

var host = builder.Build();
host.Run();
