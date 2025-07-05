using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Infra.Modules.IdentityProvider.Data.Entities;
using Microsoft.AspNetCore;

namespace Infra.Modules.IdentityProvider.Pages.Connect;

public class AuthorizeModel : PageModel
{
    private readonly UserManager<ApplicationUser> _users;
    private readonly SignInManager<ApplicationUser> _signIn;
    
    public AuthorizeModel(
        UserManager<ApplicationUser> users,
        SignInManager<ApplicationUser> signIn)
    {
        _users = users;
        _signIn = signIn;
    }

    public async Task<IActionResult> OnGetAsync()
    {
        // 1. Grab the OIDC request
        var request = HttpContext.GetOpenIddictServerRequest()
                      ?? throw new InvalidOperationException("Missing OIDC request.");

        // 2. Not logged in yet?
        if (!User.Identity?.IsAuthenticated ?? true)
        {
            // round-trip back here after login
            return Challenge(new AuthenticationProperties
            {
                RedirectUri = "/connect/authorize" + Request.QueryString
            }, IdentityConstants.ApplicationScheme);
        }

        // 3. Figure out which scopes remain to be granted
        var user  = await _users.GetUserAsync(User)
                   ?? throw new InvalidOperationException("Unknown user.");
        var clientId = request.ClientId!;
        var claimType = $"consent:{clientId}";

        // existing scopes
        var existingValue = (await _users.GetClaimsAsync(user))
                            .FirstOrDefault(c => c.Type == claimType)
                            ?.Value ?? string.Empty;
        var existing = existingValue
                       .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                       .ToHashSet(StringComparer.Ordinal);

        // the request's scopes
        var requested = request.GetScopes().ToList();
        var missing   = requested.Where(s => !existing.Contains(s)).ToList();

        if (!missing.Any())
        {
            // all already granted → issue tokens
            return IssueTokens(user, request, requested);
        }

        // 4. ask consent only for the *missing* ones
        HttpContext.Session.SetString("oidc_client_id", clientId);
        HttpContext.Session.SetString("oidc_scope", string.Join(" ", missing));
        HttpContext.Session.SetString("return_url", Request.Path + Request.QueryString);

        return Redirect("/connect/consent");
    }

    private IActionResult IssueTokens(
        ApplicationUser user,
        OpenIddictRequest request,
        IEnumerable<string> scopes)
    {
        // build your claims 
        var claims = new List<Claim>
        {
            new(OpenIddictConstants.Claims.Subject, user.Id),
            new(OpenIddictConstants.Claims.Email, user.Email ?? ""),
            new(OpenIddictConstants.Claims.Name, user.UserName ?? "")
        };

        var identity = new ClaimsIdentity(
            claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        // set scopes & resources
        principal.SetScopes(scopes);
        principal.SetResources("resource_server");

        // tell OpenIddict which claims go where
        foreach (var claim in principal.Claims)
            claim.SetDestinations(
                OpenIddictConstants.Destinations.AccessToken,
                OpenIddictConstants.Destinations.IdentityToken);

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}