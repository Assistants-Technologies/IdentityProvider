using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace Infra.Modules.IdentityProvider.Pages.Connect;

public class AuthorizeModel : PageModel
{
    public async Task<IActionResult> OnGetAsync()
    {
        var request = HttpContext.GetOpenIddictServerRequest();

        if (!User.Identity?.IsAuthenticated ?? false)
        {
            // Nie jesteś zalogowany — przekieruj do loginu
            return Challenge(
                new AuthenticationProperties
                {
                    RedirectUri = "/connect/authorize" + Request.QueryString
                },
                IdentityConstants.ApplicationScheme // albo CookieAuthenticationDefaults.AuthenticationScheme
            );
        }
        
        // 🚨 Sprawdź consent
        var consent = HttpContext.Session.GetString("consent");
        if (consent != "yes")
        {
            HttpContext.Session.SetString("oidc_client_id", request!.ClientId ?? "client");
            HttpContext.Session.SetString("oidc_scope", string.Join(" ", request.GetScopes()));
            HttpContext.Session.SetString("return_url", Request.Path + Request.QueryString);
            return Redirect("/connect/consent");
        }

        var claims = new List<Claim>
        {
            new(OpenIddictConstants.Claims.Subject, User.FindFirstValue(ClaimTypes.NameIdentifier)!),
            new(OpenIddictConstants.Claims.Email, User.FindFirstValue(ClaimTypes.Email) ?? ""),
            new(OpenIddictConstants.Claims.Name, User.Identity?.Name ?? "")
        };

        var identity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        principal.SetScopes(request!.GetScopes());
        principal.SetResources("resource_server");
        
        foreach (var claim in principal.Claims)
        {
            claim.SetDestinations(OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken);
        }
        
        Console.WriteLine($"🔐 Signing in user: {User.Identity?.Name}");
        foreach (var c in principal.Claims)
        {
            Console.WriteLine($"Claim: {c.Type} = {c.Value}");
        }

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}