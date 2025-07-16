using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Infra.Modules.IdentityProvider.Data.Entities;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Infra.Modules.IdentityProvider.Pages.Connect;

[Produces("application/json")]
public class AuthorizeModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;

    public AuthorizeModel(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager)
    {
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [HttpGet]
    public async Task<IActionResult> OnGet()
    {
        try  
        { 
            var request = HttpContext.GetOpenIddictServerRequest() ?? 
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            if (!_signInManager.IsSignedIn(User))
            {
                return Challenge(
                    new AuthenticationProperties
                    {
                        RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                            Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList())
                    },
                    IdentityConstants.ApplicationScheme);
            }

            var user = await _userManager.GetUserAsync(User) ??
                throw new InvalidOperationException("The user details cannot be retrieved.");

            var identity = new ClaimsIdentity(
                authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                nameType: OpenIddictConstants.Claims.Name,
                roleType: OpenIddictConstants.Claims.Role);

            identity.AddClaim(OpenIddictConstants.Claims.Subject, await _userManager.GetUserIdAsync(user));
            identity.AddClaim(OpenIddictConstants.Claims.Email, await _userManager.GetEmailAsync(user));
            identity.AddClaim(OpenIddictConstants.Claims.Name, await _userManager.GetUserNameAsync(user));
            identity.AddClaim("country", user.Country);
            identity.AddClaim(OpenIddictConstants.Claims.Issuer, "https://identity.assts.tech");

            var principal = new ClaimsPrincipal(identity);
            principal.SetScopes(request.GetScopes());
            principal.SetResources("resource_server");

            foreach (var claim in principal.Claims)
            {
                claim.SetDestinations(GetDestinations(claim, principal));
            }

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
        catch (Exception ex)
        {
            return BadRequest(new
            {
                error = OpenIddictConstants.Errors.ServerError,
                error_description = ex.Message
            });
        }
    }

    private static IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
    {
        switch (claim.Type)
        {
            case OpenIddictConstants.Claims.Name:
                yield return OpenIddictConstants.Destinations.AccessToken;
                if (principal.HasScope(OpenIddictConstants.Scopes.Profile))
                    yield return OpenIddictConstants.Destinations.IdentityToken;
                break;

            case OpenIddictConstants.Claims.Email:
                yield return OpenIddictConstants.Destinations.AccessToken;
                if (principal.HasScope(OpenIddictConstants.Scopes.Email))
                    yield return OpenIddictConstants.Destinations.IdentityToken;
                break;

            case "country":
                yield return OpenIddictConstants.Destinations.AccessToken;
                if (principal.HasScope(OpenIddictConstants.Scopes.Profile))
                {
                    yield return OpenIddictConstants.Destinations.IdentityToken;
                    yield return "userinfo";
                }
                break;

            case OpenIddictConstants.Claims.Subject:
            case OpenIddictConstants.Claims.Issuer:
                yield return OpenIddictConstants.Destinations.AccessToken;
                yield return OpenIddictConstants.Destinations.IdentityToken;
                break;

            default:
                yield return OpenIddictConstants.Destinations.AccessToken;
                break;
        }
    }
}