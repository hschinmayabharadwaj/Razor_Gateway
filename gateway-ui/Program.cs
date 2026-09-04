using System.Text.Json;
using GatewayUI.Components;
using GatewayUI.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddHttpClient();
builder.Services.AddSingleton<IGatewayApi, GatewayApiService>();
builder.Services.AddSingleton<AuditStreamService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<AuditStreamService>());
builder.Services.AddSingleton<PaymentAuditService>();
builder.Services.AddSingleton<RazorpayPaymentService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapPost("/api/payments/razorpay/order", async (CreateRazorpayOrderRequest request, RazorpayPaymentService payments, CancellationToken cancellationToken) =>
{
    try
    {
        var result = await payments.CreateOrderAsync(request, cancellationToken);
        return result.Order is null
            ? Results.BadRequest(new { error = result.Error })
            : Results.Ok(result.Order);
    }
    catch (InvalidOperationException ex)
    {
        return Results.Problem(ex.Message, statusCode: StatusCodes.Status503ServiceUnavailable);
    }
});

app.MapPost("/api/payments/razorpay/verify", async (VerifyRazorpayPaymentRequest request, RazorpayPaymentService payments, CancellationToken cancellationToken) =>
{
    try
    {
        var result = await payments.VerifyPaymentAsync(request, cancellationToken);
        return result.Ok ? Results.Ok(result) : Results.BadRequest(result);
    }
    catch (InvalidOperationException ex)
    {
        return Results.Problem(ex.Message, statusCode: StatusCodes.Status503ServiceUnavailable);
    }
});

app.MapPost("/webhooks/razorpay", async (HttpRequest request, RazorpayPaymentService payments, CancellationToken cancellationToken) =>
{
    var signature = request.Headers["X-Razorpay-Signature"].ToString();
    if (string.IsNullOrWhiteSpace(signature))
    {
        return Results.Unauthorized();
    }

    using var reader = new StreamReader(request.Body);
    var rawBody = await reader.ReadToEndAsync(cancellationToken);
    try
    {
        var result = await payments.ProcessWebhookAsync(signature, rawBody, cancellationToken);
        return result.Ok ? Results.Ok(result) : Results.Unauthorized();
    }
    catch (JsonException)
    {
        return Results.BadRequest(new { error = "Webhook body is not valid JSON." });
    }
    catch (InvalidOperationException ex)
    {
        return Results.Problem(ex.Message, statusCode: StatusCodes.Status503ServiceUnavailable);
    }
});

app.Run();
