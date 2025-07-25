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

        
            if (await scopeMgr.FindByNameAsync("api:store") is null)
            {
                await scopeMgr.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name        = "api:store",
                    DisplayName = "Store API Access",
                    Resources   = { "store-api" }
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