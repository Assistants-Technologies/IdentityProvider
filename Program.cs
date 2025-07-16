using System;
using System.Net;
using Infra.Modules.IdentityProvider.Data;
using Infra.Modules.IdentityProvider.Data.Entities;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Services configuration
if (builder.Environment.IsDevelopment())
{
    builder.Services
        .AddRazorPages()
        .AddRazorRuntimeCompilation();
}
else
{
    builder.Services.AddRazorPages();
}

// Database context
builder.Services.AddDbContext<IdentityProviderDbContext>(options =>
{
    options.UseNpgsql(Environment.GetEnvironmentVariable("IDP_CONNECTION_STRING")!);
    options.UseOpenIddict();
});

// OpenIddict
builder.Services.AddOpenIddict()
    .AddCore(options => options.UseEntityFrameworkCore().UseDbContext<IdentityProviderDbContext>())
    .AddServer(options =>
    {
        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetTokenEndpointUris("/connect/token")
               .SetUserInfoEndpointUris("/connect/userinfo")
               .SetEndSessionEndpointUris("/connect/logout");

        options.AllowAuthorizationCodeFlow()
               .AllowRefreshTokenFlow();

        options.SetIssuer(new Uri(Environment.GetEnvironmentVariable("IDP_ISSUER")!));

        options.RegisterScopes(
            OpenIddictConstants.Scopes.OpenId,
            OpenIddictConstants.Scopes.Email,
            OpenIddictConstants.Scopes.Profile,
            OpenIddictConstants.Scopes.OfflineAccess);

        options.RegisterClaims("country"); // Rejestracja custom claima

        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableUserInfoEndpointPassthrough()
               .EnableEndSessionEndpointPassthrough();

        // Obsługa błędów
        options.AddEventHandler<OpenIddictServerEvents.ProcessErrorContext>(builder =>
            builder.UseInlineHandler(context =>
            {
                return default;
            }));
        });

// Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.SignIn.RequireConfirmedAccount = false;
    options.User.AllowedUserNameCharacters = 
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<IdentityProviderDbContext>()
.AddDefaultTokenProviders();

// Cookie
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/login";
    options.AccessDeniedPath = "/accessdenied";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(15);
    options.SlidingExpiration = true;
});

// Session
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(5);
    options.Cookie.IsEssential = true;
});

var app = builder.Build();

// Database migration and initialization
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<IdentityProviderDbContext>();
    await db.Database.MigrateAsync();
    
    // Inicjalizacja danych OpenIddict
    await OpenIddictSeeder.SeedAsync(scope.ServiceProvider);
}

// Middleware configuration
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

await app.RunAsync();