using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GatewayUI.Services;

public sealed record CreateRazorpayOrderRequest(long Amount, string Currency = "INR", string? Receipt = null);
public sealed record RazorpayOrderResponse(string OrderId, long Amount, string Currency, string KeyId);
public sealed record VerifyRazorpayPaymentRequest(string OrderId, string PaymentId, string Signature);
public sealed record PaymentOperationResult(bool Ok, string? Message = null, string? EventId = null);

public sealed class RazorpayPaymentService
{
    private readonly IHttpClientFactory _clientFactory;
    private readonly IConfiguration _configuration;
    private readonly PaymentAuditService _audit;
    private readonly ConcurrentDictionary<string, byte> _processedWebhookEvents = new();

    public RazorpayPaymentService(IHttpClientFactory clientFactory, IConfiguration configuration, PaymentAuditService audit)
    {
        _clientFactory = clientFactory;
        _configuration = configuration;
        _audit = audit;
    }

    public string KeyId => RequiredSetting("RAZORPAY_KEY_ID", "Razorpay:KeyId");

    public async Task<(RazorpayOrderResponse? Order, string? Error)> CreateOrderAsync(CreateRazorpayOrderRequest request, CancellationToken cancellationToken)
    {
        if (request.Amount < 100)
        {
            return (null, "Amount must be at least 100 paise.");
        }
        if (!string.Equals(request.Currency, "INR", StringComparison.OrdinalIgnoreCase))
        {
            return (null, "This first integration supports INR only.");
        }

        var keySecret = RequiredSetting("RAZORPAY_KEY_SECRET", "Razorpay:KeySecret");
        var payload = new
        {
            amount = request.Amount,
            currency = request.Currency.ToUpperInvariant(),
            receipt = string.IsNullOrWhiteSpace(request.Receipt) ? $"rcpt_{Guid.NewGuid():N}" : request.Receipt,
            notes = new { source = "razorops" }
        };

        using var client = _clientFactory.CreateClient();
        using var message = new HttpRequestMessage(HttpMethod.Post, "https://api.razorpay.com/v1/orders")
        {
            Content = JsonContent.Create(payload)
        };
        var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{KeyId}:{keySecret}"));
        message.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);

        try
        {
            using var response = await client.SendAsync(message, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return (null, $"Razorpay order creation failed ({(int)response.StatusCode}).");
            }

            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            return (new RazorpayOrderResponse(
                root.GetProperty("id").GetString()!,
                root.GetProperty("amount").GetInt64(),
                root.GetProperty("currency").GetString()!,
                KeyId), null);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return (null, "Razorpay request timed out.");
        }
        catch (Exception ex)
        {
            return (null, $"Razorpay request failed: {ex.Message}");
        }
    }

    public async Task<PaymentOperationResult> VerifyPaymentAsync(VerifyRazorpayPaymentRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.OrderId) || string.IsNullOrWhiteSpace(request.PaymentId) || string.IsNullOrWhiteSpace(request.Signature))
        {
            return new(false, "Order ID, payment ID, and signature are required.");
        }

        var secret = RequiredSetting("RAZORPAY_KEY_SECRET", "Razorpay:KeySecret");
        var expected = HmacHex(secret, $"{request.OrderId}|{request.PaymentId}");
        var valid = CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected),
            Encoding.UTF8.GetBytes(request.Signature));
        var eventId = $"payment.verified.{request.PaymentId}";
        await _audit.AppendAsync(eventId, "payment.verified", valid ? "verified" : "rejected", new
        {
            orderId = request.OrderId,
            paymentId = request.PaymentId,
            valid
        }, cancellationToken);

        return valid
            ? new(true, "Payment signature verified.", eventId)
            : new(false, "Payment signature did not match.", eventId);
    }

    public async Task<PaymentOperationResult> ProcessWebhookAsync(string signature, string rawBody, CancellationToken cancellationToken)
    {
        var secret = RequiredSetting("RAZORPAY_WEBHOOK_SECRET", "Razorpay:WebhookSecret");
        var expected = HmacHex(secret, rawBody);
        var valid = CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected),
            Encoding.UTF8.GetBytes(signature.Trim()));
        if (!valid)
        {
            return new(false, "Invalid Razorpay webhook signature.");
        }

        using var document = JsonDocument.Parse(rawBody);
        var root = document.RootElement;
        var eventName = root.TryGetProperty("event", out var eventProperty) ? eventProperty.GetString() ?? "unknown" : "unknown";
        var eventId = root.TryGetProperty("payload", out var payload) && payload.TryGetProperty("payment", out var payment)
            && payment.TryGetProperty("entity", out var entity) && entity.TryGetProperty("id", out var paymentId)
            ? paymentId.GetString() ?? $"webhook.{Guid.NewGuid():N}"
            : $"webhook.{Guid.NewGuid():N}";

        if (!_processedWebhookEvents.TryAdd(eventId, 0))
        {
            return new(true, "Webhook already processed.", eventId);
        }

        await _audit.AppendAsync(eventId, eventName, "accepted", new { eventName }, cancellationToken);
        return new(true, "Webhook accepted.", eventId);
    }

    private string RequiredSetting(string environmentName, string configurationName)
    {
        var value = Environment.GetEnvironmentVariable(environmentName);
        if (!string.IsNullOrWhiteSpace(value))
        {
            return value;
        }
        value = _configuration[configurationName];
        if (!string.IsNullOrWhiteSpace(value))
        {
            return value;
        }
        throw new InvalidOperationException($"Payment configuration '{environmentName}' is not set.");
    }

    private static string HmacHex(string secret, string value)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }
}

public sealed class PaymentAuditService
{
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly IHttpClientFactory _clientFactory;
    private readonly ILogger<PaymentAuditService> _logger;
    private readonly string _goStreamBaseUrl;
    private string _previousHash = "0000000000000000000000000000000000000000000000000000000000000000";

    public PaymentAuditService(IHostEnvironment environment, IConfiguration configuration, IHttpClientFactory clientFactory, ILogger<PaymentAuditService> logger)
    {
        var configured = configuration["PaymentAuditPath"] ?? "../data/payment-webhooks.jsonl";
        _path = Path.GetFullPath(Path.Combine(environment.ContentRootPath, configured));
        _clientFactory = clientFactory;
        _logger = logger;
        _goStreamBaseUrl = configuration["GO_BACKEND_URL"] ?? "http://localhost:8090";
    }

    public async Task AppendAsync(string eventId, string eventType, string state, object details, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var entry = new PaymentAuditEntry(eventId, DateTimeOffset.UtcNow, eventType, state, details, _previousHash, "");
            var unsigned = JsonSerializer.Serialize(entry with { Hash = "" });
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(_previousHash + unsigned))).ToLowerInvariant();
            var line = JsonSerializer.Serialize(entry with { Hash = hash }) + Environment.NewLine;
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            await File.AppendAllTextAsync(_path, line, Encoding.UTF8, cancellationToken);
            _previousHash = hash;
        }
        finally
        {
            _gate.Release();
        }

        // Best-effort forward to Go stream server so the event appears on the
        // live SSE audit stream. Failures are logged but never propagated — the
        // local hash chain is the source of truth for payment audit.
        _ = ForwardToGoAsync(eventId, eventType, state, details);
    }

    private async Task ForwardToGoAsync(string eventId, string eventType, string state, object details)
    {
        try
        {
            using var client = _clientFactory.CreateClient();
            client.Timeout = TimeSpan.FromSeconds(5);
            var payload = new
            {
                eventId,
                eventType,
                state,
                details = JsonSerializer.Serialize(details)
            };
            using var request = new HttpRequestMessage(HttpMethod.Post, $"{_goStreamBaseUrl}/payment-event")
            {
                Content = JsonContent.Create(payload)
            };
            // Use the admin key so the Go auth gate accepts the write.
            request.Headers.Add("X-API-Key", "admin_key_demo");
            using var response = await client.SendAsync(request);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Forward to Go /payment-event returned {Status}", (int)response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to forward payment event {EventId} to Go stream server", eventId);
        }
    }

    private sealed record PaymentAuditEntry(
        [property: JsonPropertyName("eventId")] string EventId,
        [property: JsonPropertyName("timestamp")] DateTimeOffset Timestamp,
        [property: JsonPropertyName("eventType")] string EventType,
        [property: JsonPropertyName("state")] string State,
        [property: JsonPropertyName("details")] object Details,
        [property: JsonPropertyName("prevHash")] string PreviousHash,
        [property: JsonPropertyName("hash")] string Hash);
}
