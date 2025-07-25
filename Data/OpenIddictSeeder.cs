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
            
            if (await scopeMgr.FindByNameAsync("api:store") is null)
            {
                await scopeMgr.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name        = "api:store",
                    DisplayName = "Store API Access",
                    Resources   = { "store-api" }
                });
            }

            // 4. Dashboard client (ma dostęp do wszystkiego)
            if (await appMgr.FindByClientIdAsync(Environment.GetEnvironmentVariable("IDP_ACC_PANEL_CLIENT_ID")!) is null)
            {
                await appMgr.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientType    = ClientTypes.Confidential,
                    ClientId      =  Environment.GetEnvironmentVariable("IDP_ACC_PANEL_CLIENT_ID"),
                    ClientSecret  = Environment.GetEnvironmentVariable("IDP_ACC_PANEL_CLIENT_SECRET"),
                    DisplayName   = Environment.GetEnvironmentVariable("IDP_ACC_PANEL_CLIENT_DISPLAY_NAME"),
                    RedirectUris  = { new Uri(Environment.GetEnvironmentVariable("IDP_ACC_PANEL_REDIRECT_URI")!) },
                    PostLogoutRedirectUris = { new Uri(Environment.GetEnvironmentVariable("IDP_ACC_PANEL_POST_LOGOUT_REDIRECT_URI")!) },
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

                        Permissions.Prefixes.Scope + "api:store",
                        Permissions.Prefixes.Scope + "api:account",
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
            
            if (await appMgr.FindByClientIdAsync(Environment.GetEnvironmentVariable("COMMERCE_CLIENT_ID")!) is null)
            {
                await appMgr.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientType    = ClientTypes.Confidential,
                    ClientId      =  Environment.GetEnvironmentVariable("COMMERCE_CLIENT_ID"),
                    ClientSecret  = Environment.GetEnvironmentVariable("COMMERCE_CLIENT_SECRET"),
                    DisplayName   = Environment.GetEnvironmentVariable("COMMERCE_CLIENT_DISPLAY_NAME"),
                    RedirectUris  = { new Uri(Environment.GetEnvironmentVariable("COMMERCE_REDIRECT_URI")!) },
                    PostLogoutRedirectUris = { new Uri(Environment.GetEnvironmentVariable("COMMERCE_POST_LOGOUT_REDIRECT_URI")!) },
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

                        Permissions.Prefixes.Scope + "api:store",
                        Permissions.Prefixes.Scope + "api:account",
                    }
                });
            }
            
            if (await appMgr.FindByClientIdAsync(Environment.GetEnvironmentVariable("DBD_OIDC_CLIENT_ID")!) is null)
            {
                await appMgr.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ClientType    = ClientTypes.Confidential,
                    ClientId      =  Environment.GetEnvironmentVariable("DBD_OIDC_CLIENT_ID"),
                    ClientSecret  = Environment.GetEnvironmentVariable("DBD_OIDC_CLIENT_SECRET"),
                    DisplayName   = Environment.GetEnvironmentVariable("DBD_OIDC_CLIENT_DISPLAY_NAME"),
                    RedirectUris  = { new Uri(Environment.GetEnvironmentVariable("DBD_OIDC_REDIRECT_URI")!), new Uri("https://oauth.pstmn.io/v1/callback") },
                    PostLogoutRedirectUris = { new Uri(Environment.GetEnvironmentVariable("DBD_OIDC_POST_LOGOUT_REDIRECT_URI")!) },
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
                        Scopes.OfflineAccess, }
                });
            }
        }
    }