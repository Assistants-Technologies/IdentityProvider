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
using OpenIddict.Server;

var builder = WebApplication.CreateBuilder(args);

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

// === DB + OpenIddict ===
builder.Services.AddDbContext<IdentityProviderDbContext>(options =>
{
    options.UseNpgsql(Environment.GetEnvironmentVariable("IDP_CONNECTION_STRING")!);
    options.UseOpenIddict();
});

// === OpenIddict ===
builder.Services.AddOpenIddict()
    .AddCore(opt => opt.UseEntityFrameworkCore().UseDbContext<IdentityProviderDbContext>())
    .AddServer(opt =>
    {
        opt.SetAuthorizationEndpointUris("/connect/authorize")
            .SetTokenEndpointUris("/connect/token")
            .SetUserInfoEndpointUris("/connect/userinfo")
            .SetEndSessionEndpointUris("/connect/logout");

        opt.AllowAuthorizationCodeFlow()
            .AllowClientCredentialsFlow()
            .AllowRefreshTokenFlow();
        
        opt.SetIssuer(Environment.GetEnvironmentVariable("IDP_ISSUER")!);
        

        opt.AddEventHandler<OpenIddictServerEvents.ApplyAuthorizationResponseContext>(builder =>
        {
            builder.UseInlineHandler(context =>
            {
                if (!string.IsNullOrEmpty(context.Response.Error))
                {
                    var error   = context.Response.Error;
                    var desc    = context.Response.ErrorDescription ?? "";
                    var message = WebUtility.UrlEncode($"{error}: {desc}");

                    var clientId = context.Request.ClientId ?? "unknown_client";

                    var http    = context.Transaction.GetHttpRequest().HttpContext.Request;
                    var original = WebUtility.UrlEncode(http.Path + http.QueryString);

                    var redirect = $"/Error?code=400" +
                                   $"&message={message}" +
                                   $"&client_id={WebUtility.UrlEncode(clientId)}" +
                                   $"&original={original}";

                    context.Transaction
                        .GetHttpRequest()
                        .HttpContext
                        .Response
                        .Redirect(redirect);

                    context.HandleRequest();
                }

                return default;
            });
        });

        opt.RegisterScopes("openid", "email", "profile", "offline_access");

        opt.UseAspNetCore()
            .DisableTransportSecurityRequirement()
            .EnableAuthorizationEndpointPassthrough()
            .EnableStatusCodePagesIntegration();

        opt.AddDevelopmentEncryptionCertificate();
        opt.AddDevelopmentSigningCertificate();
    })
    .AddValidation(opt =>
    {
        opt.UseLocalServer();
        opt.UseAspNetCore();
    });

// === Identity + UI ===

builder.Services
    .AddIdentity<ApplicationUser, IdentityRole>(options => {
        options.SignIn.RequireConfirmedAccount = false;
    })
    .AddEntityFrameworkStores<IdentityProviderDbContext>()
    .AddDefaultTokenProviders();
 
// === Cookie auth config ===
builder.Services.ConfigureApplicationCookie(opt =>
{
    opt.LoginPath = "/login";
    opt.AccessDeniedPath = "/accessdenied";
    opt.ExpireTimeSpan = TimeSpan.FromMinutes(15);
    opt.SlidingExpiration = true;
});

// === Session ===
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(5);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var db = scope.ServiceProvider.GetRequiredService<IdentityProviderDbContext>();
    await db.Database.MigrateAsync();

    try
    {
        await OpenIddictSeeder.SeedAsync(services);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"OpenIddict seeding failed: {ex.Message}");
        throw;
    }
}

app.UseExceptionHandler("/Error");
app.UseStatusCodePagesWithReExecute("/Error", "?code={0}");

// === Middleware ===
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseSession(); 

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

await app.RunAsync();