using Infra.Modules.IdentityProvider.Data.Entities;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Infra.Modules.IdentityProvider.Data;

public static class OpenIddictSeeder
    {
        public static async Task SeedAsync(IServiceProvider provider)
        {
            // 1. Admin user
            var userMgr = provider.GetRequiredService<UserManager<ApplicationUser>>();
            var appMgr  = provider.GetRequiredService<IOpenIddictApplicationManager>();
            var scopeMgr = provider.GetRequiredService<IOpenIddictScopeManager>();

            var user = await userMgr.FindByEmailAsync("admin@local");
            if (user == null)
            {
                user = new ApplicationUser
                {
                    UserName = "admin@local",
                    Email     = "admin@local",
                    EmailConfirmed = true
                };
                await userMgr.CreateAsync(user, "Admin123!");
                await userMgr.AddClaimAsync(user,
                    new System.Security.Claims.Claim(Claims.Name, "Admin"));
            }

            // 2. Legacy „my-client” (opcjonalnie)
            if (await appMgr.FindByClientIdAsync("my-client") is null)
            {
                await appMgr.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientType    = ClientTypes.Confidential,
                    ClientId      = "my-client",
                    ClientSecret  = "super-secret",
                    DisplayName   = "My Client",
                    RedirectUris  = { new Uri("https://client.localhost:3000/callback") },
                    PostLogoutRedirectUris = { new Uri("https://client.localhost:3000/logout") },
                    Permissions =
                    {
                        // Endpoints
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Token,
                        Permissions.Endpoints.Introspection,

                        // Grant types
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.GrantTypes.ClientCredentials,

                        // Response types
                        Permissions.ResponseTypes.Code,

                        // Scopes
                        Scopes.OpenId,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Scopes.OfflineAccess
                    }
                });
            }

            // 3. Definicja scope'ów dla API
            if (await scopeMgr.FindByNameAsync("api:store") is null)
            {
                await scopeMgr.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name        = "api:store",
                    DisplayName = "Store API Access",
                    Resources   = { "store-api" }
                });
            }

            if (await scopeMgr.FindByNameAsync("api:account") is null)
            {
                await scopeMgr.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name        = "api:account",
                    DisplayName = "Account API Access",
                    Resources   = { "account-api" }
                });
            }

            if (await scopeMgr.FindByNameAsync("api:dashboard") is null)
            {
                await scopeMgr.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name        = "api:dashboard",
                    DisplayName = "Dashboard API Access",
                    Resources   = { "dashboard-api" }
                });
            }

            // 4. Dashboard client (ma dostęp do wszystkiego)
            if (await appMgr.FindByClientIdAsync("dashboard-client") is null)
            {
                await appMgr.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientType    = ClientTypes.Confidential,
                    ClientId      = "dashboard-client",
                    ClientSecret  = "dashboard-secret",
                    DisplayName   = "Dashboard App",
                    RedirectUris  = { new Uri("https://dashboard.localhost:3000/callback") },
                    PostLogoutRedirectUris = { new Uri("https://dashboard.localhost:3000/logout") },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.ResponseTypes.Code,

                        Scopes.OpenId,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Scopes.OfflineAccess,

                        // Uprawnienia do API
                        Permissions.Prefixes.Scope + "api:store",
                        Permissions.Prefixes.Scope + "api:account",
                        Permissions.Prefixes.Scope + "api:dashboard"
                    }
                });
            }

            // 5. Mobile client (tylko do account API)
            if (await appMgr.FindByClientIdAsync("mobile-client") is null)
            {
                await appMgr.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientType    = ClientTypes.Public,
                    ClientId      = "mobile-client",
                    DisplayName   = "Mobile App",
                    RedirectUris  = { new Uri("com.app.mobile://callback") },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.ResponseTypes.Code,

                        Scopes.OpenId,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Scopes.OfflineAccess,

                        // Tylko account API
                        Permissions.Prefixes.Scope + "api:account"
                    }
                });
            }
        }
    }