//! API Key Management Module
//! Provides specialized handling for API keys with expiration, rotation, and provider templates

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

/// Supported API key providers with specific handling
pub const Provider = enum {
    aws,
    github,
    stripe,
    openai,
    anthropic,
    google_cloud,
    azure,
    digitalocean,
    heroku,
    sendgrid,
    twilio,
    slack,
    discord,
    generic,

    pub fn fromString(str: []const u8) ?Provider {
        inline for (std.meta.fields(Provider)) |field| {
            if (std.mem.eql(u8, str, field.name)) {
                return @enumFromInt(field.value);
            }
        }
        return null;
    }

    pub fn toString(self: Provider) []const u8 {
        return @tagName(self);
    }
};

/// Export format for API keys
pub const ExportFormat = enum {
    env, // Shell environment variables (export KEY=value)
    json, // JSON object
    dotenv, // .env file format (KEY=value)
    yaml, // YAML format
};

/// API key field definition for multi-field credentials
pub const KeyField = struct {
    name: []const u8,
    value: []const u8,
    env_var: ?[]const u8 = null, // Environment variable name for export

    pub fn deinit(self: *KeyField, allocator: Allocator) void {
        allocator.free(self.name);
        allocator.free(self.value);
        if (self.env_var) |env| {
            allocator.free(env);
        }
    }
};

/// API key metadata for tracking expiration and rotation
pub const ApiKeyMetadata = struct {
    provider: Provider,
    scopes: ?ArrayList([]const u8) = null, // API scopes/permissions
    created_at: i64,
    expires_at: ?i64 = null, // Unix timestamp when key expires
    last_rotated: ?i64 = null, // Last rotation timestamp
    rotation_days: ?u32 = null, // Recommended rotation interval in days
    project_id: ?[]const u8 = null, // Provider-specific project/account ID
    region: ?[]const u8 = null, // For cloud providers (us-east-1, etc.)
    environment: ?[]const u8 = null, // dev, staging, production
    notes: ?[]const u8 = null, // Additional notes

    pub fn init(provider: Provider) ApiKeyMetadata {
        return ApiKeyMetadata{
            .provider = provider,
            .created_at = std.time.timestamp(),
        };
    }

    pub fn deinit(self: *ApiKeyMetadata, allocator: Allocator) void {
        if (self.scopes) |*scopes| {
            for (scopes.items) |scope| {
                allocator.free(scope);
            }
            scopes.deinit(allocator);
        }
        if (self.project_id) |pid| allocator.free(pid);
        if (self.region) |reg| allocator.free(reg);
        if (self.environment) |env| allocator.free(env);
        if (self.notes) |n| allocator.free(n);
    }

    /// Check if the key is expired
    pub fn isExpired(self: *const ApiKeyMetadata) bool {
        if (self.expires_at) |expiry| {
            return std.time.timestamp() >= expiry;
        }
        return false;
    }

    /// Check if the key should be rotated (based on last rotation + interval)
    pub fn needsRotation(self: *const ApiKeyMetadata) bool {
        if (self.rotation_days == null) return false;

        const last_rotation = self.last_rotated orelse self.created_at;
        const rotation_interval = self.rotation_days.? * 86400; // days to seconds
        const next_rotation = last_rotation + rotation_interval;

        return std.time.timestamp() >= next_rotation;
    }

    /// Days until expiration (null if no expiration set)
    pub fn daysUntilExpiration(self: *const ApiKeyMetadata) ?i64 {
        if (self.expires_at) |expiry| {
            const now = std.time.timestamp();
            const seconds_remaining = expiry - now;
            return @divFloor(seconds_remaining, 86400);
        }
        return null;
    }

    /// Days since last rotation
    pub fn daysSinceRotation(self: *const ApiKeyMetadata) i64 {
        const last_rotation = self.last_rotated orelse self.created_at;
        const now = std.time.timestamp();
        return @divFloor(now - last_rotation, 86400);
    }
};

/// Provider template defining required fields and defaults
pub const ProviderTemplate = struct {
    provider: Provider,
    display_name: []const u8,
    fields: []const FieldTemplate,
    default_rotation_days: ?u32,
    documentation_url: ?[]const u8,

    pub const FieldTemplate = struct {
        name: []const u8,
        env_var: []const u8,
        required: bool,
        description: []const u8,
    };
};

/// Get provider template for a given provider
pub fn getProviderTemplate(provider: Provider) ProviderTemplate {
    return switch (provider) {
        .aws => .{
            .provider = .aws,
            .display_name = "Amazon Web Services",
            .fields = &.{
                .{ .name = "access_key_id", .env_var = "AWS_ACCESS_KEY_ID", .required = true, .description = "AWS Access Key ID" },
                .{ .name = "secret_access_key", .env_var = "AWS_SECRET_ACCESS_KEY", .required = true, .description = "AWS Secret Access Key" },
                .{ .name = "session_token", .env_var = "AWS_SESSION_TOKEN", .required = false, .description = "AWS Session Token (optional)" },
            },
            .default_rotation_days = 90,
            .documentation_url = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
        },
        .github => .{
            .provider = .github,
            .display_name = "GitHub",
            .fields = &.{
                .{ .name = "token", .env_var = "GITHUB_TOKEN", .required = true, .description = "GitHub Personal Access Token" },
            },
            .default_rotation_days = 365,
            .documentation_url = "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
        },
        .stripe => .{
            .provider = .stripe,
            .display_name = "Stripe",
            .fields = &.{
                .{ .name = "secret_key", .env_var = "STRIPE_SECRET_KEY", .required = true, .description = "Stripe Secret Key" },
                .{ .name = "publishable_key", .env_var = "STRIPE_PUBLISHABLE_KEY", .required = false, .description = "Stripe Publishable Key" },
            },
            .default_rotation_days = 180,
            .documentation_url = "https://stripe.com/docs/keys",
        },
        .openai => .{
            .provider = .openai,
            .display_name = "OpenAI",
            .fields = &.{
                .{ .name = "api_key", .env_var = "OPENAI_API_KEY", .required = true, .description = "OpenAI API Key" },
                .{ .name = "organization", .env_var = "OPENAI_ORGANIZATION", .required = false, .description = "OpenAI Organization ID" },
            },
            .default_rotation_days = 90,
            .documentation_url = "https://platform.openai.com/docs/api-reference/authentication",
        },
        .anthropic => .{
            .provider = .anthropic,
            .display_name = "Anthropic",
            .fields = &.{
                .{ .name = "api_key", .env_var = "ANTHROPIC_API_KEY", .required = true, .description = "Anthropic API Key" },
            },
            .default_rotation_days = 90,
            .documentation_url = "https://docs.anthropic.com/claude/reference/getting-started-with-the-api",
        },
        .google_cloud => .{
            .provider = .google_cloud,
            .display_name = "Google Cloud Platform",
            .fields = &.{
                .{ .name = "api_key", .env_var = "GOOGLE_API_KEY", .required = true, .description = "Google Cloud API Key" },
                .{ .name = "project_id", .env_var = "GOOGLE_CLOUD_PROJECT", .required = false, .description = "GCP Project ID" },
            },
            .default_rotation_days = 90,
            .documentation_url = "https://cloud.google.com/docs/authentication/api-keys",
        },
        .azure => .{
            .provider = .azure,
            .display_name = "Microsoft Azure",
            .fields = &.{
                .{ .name = "subscription_key", .env_var = "AZURE_SUBSCRIPTION_KEY", .required = true, .description = "Azure Subscription Key" },
            },
            .default_rotation_days = 90,
            .documentation_url = "https://learn.microsoft.com/en-us/azure/api-management/api-management-subscriptions",
        },
        .digitalocean => .{
            .provider = .digitalocean,
            .display_name = "DigitalOcean",
            .fields = &.{
                .{ .name = "token", .env_var = "DIGITALOCEAN_TOKEN", .required = true, .description = "DigitalOcean API Token" },
            },
            .default_rotation_days = 180,
            .documentation_url = "https://docs.digitalocean.com/reference/api/create-personal-access-token/",
        },
        .heroku => .{
            .provider = .heroku,
            .display_name = "Heroku",
            .fields = &.{
                .{ .name = "api_key", .env_var = "HEROKU_API_KEY", .required = true, .description = "Heroku API Key" },
            },
            .default_rotation_days = 365,
            .documentation_url = "https://devcenter.heroku.com/articles/authentication",
        },
        .sendgrid => .{
            .provider = .sendgrid,
            .display_name = "SendGrid",
            .fields = &.{
                .{ .name = "api_key", .env_var = "SENDGRID_API_KEY", .required = true, .description = "SendGrid API Key" },
            },
            .default_rotation_days = 90,
            .documentation_url = "https://docs.sendgrid.com/ui/account-and-settings/api-keys",
        },
        .twilio => .{
            .provider = .twilio,
            .display_name = "Twilio",
            .fields = &.{
                .{ .name = "account_sid", .env_var = "TWILIO_ACCOUNT_SID", .required = true, .description = "Twilio Account SID" },
                .{ .name = "auth_token", .env_var = "TWILIO_AUTH_TOKEN", .required = true, .description = "Twilio Auth Token" },
            },
            .default_rotation_days = 90,
            .documentation_url = "https://www.twilio.com/docs/iam/credentials/api-keys",
        },
        .slack => .{
            .provider = .slack,
            .display_name = "Slack",
            .fields = &.{
                .{ .name = "token", .env_var = "SLACK_TOKEN", .required = true, .description = "Slack Bot Token" },
            },
            .default_rotation_days = 365,
            .documentation_url = "https://api.slack.com/authentication/token-types",
        },
        .discord => .{
            .provider = .discord,
            .display_name = "Discord",
            .fields = &.{
                .{ .name = "token", .env_var = "DISCORD_TOKEN", .required = true, .description = "Discord Bot Token" },
            },
            .default_rotation_days = 365,
            .documentation_url = "https://discord.com/developers/docs/topics/oauth2",
        },
        .generic => .{
            .provider = .generic,
            .display_name = "Generic API Key",
            .fields = &.{
                .{ .name = "api_key", .env_var = "API_KEY", .required = true, .description = "API Key" },
            },
            .default_rotation_days = 90,
            .documentation_url = null,
        },
    };
}

/// List all available providers
pub fn listProviders(allocator: Allocator) ![]Provider {
    const providers = [_]Provider{
        .aws, .github, .stripe, .openai, .anthropic,
        .google_cloud, .azure, .digitalocean, .heroku,
        .sendgrid, .twilio, .slack, .discord, .generic,
    };
    return try allocator.dupe(Provider, &providers);
}
