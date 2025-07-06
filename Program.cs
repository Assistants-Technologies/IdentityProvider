using System.Net;
using Infra.Modules.IdentityProvider;
using Infra.Modules.IdentityProvider.Data;
using Infra.Modules.IdentityProvider.Data.Entities;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
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
    options.UseNpgsql(Environment.GetEnvironmentVariable("IDP_CONNECTION_STRING"));
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
            .EnableAuthorizationEndpointPassthrough()
            .DisableTransportSecurityRequirement()
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