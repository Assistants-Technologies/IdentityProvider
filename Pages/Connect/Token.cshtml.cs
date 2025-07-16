using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Infra.Modules.IdentityProvider.Pages.Connect;
 
[IgnoreAntiforgeryToken]
[Produces("application/json")]
public class TokenModel : PageModel
{
    private readonly IOpenIddictApplicationManager _applicationManager;

    public TokenModel(IOpenIddictApplicationManager applicationManager)
    {
        _applicationManager = applicationManager;
    }

    [HttpPost]
    public async Task<IActionResult> OnPost()
    {
        try
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
            {
                return JsonError(OpenIddictConstants.Errors.UnsupportedGrantType,
                    "Only authorization code and refresh token grant types are supported.");
            }

            var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
                throw new InvalidOperationException("The application details cannot be found.");

            var principal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;
            if (principal == null)
            {
                return JsonError(OpenIddictConstants.Errors.InvalidGrant,
                    "The token is no longer valid.");
            }

            var identity = new ClaimsIdentity(principal.Identity);
            foreach (var claim in principal.Claims)
            {
                claim.SetDestinations(GetDestinations(claim, principal));
            }

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
        catch (Exception ex)
        {
            return JsonError(OpenIddictConstants.Errors.ServerError,
                $"An unexpected error occurred: {ex.Message}");
        }
    }

    private static IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
    {
        switch (claim.Type)
        {
            case OpenIddictConstants.Claims.Name:
                if (principal.HasScope(OpenIddictConstants.Scopes.Profile))
                    yield return OpenIddictConstants.Destinations.AccessToken;
                break;

            case OpenIddictConstants.Claims.Email:
                if (principal.HasScope(OpenIddictConstants.Scopes.Email))
                    yield return OpenIddictConstants.Destinations.AccessToken;
                break;

            case "country":
                if (principal.HasScope(OpenIddictConstants.Scopes.Profile))
                    yield return OpenIddictConstants.Destinations.AccessToken;
                break;

            case OpenIddictConstants.Claims.Subject:
                yield return OpenIddictConstants.Destinations.AccessToken;
                break;

            default:
                yield return OpenIddictConstants.Destinations.AccessToken;
                break;
        }
    }

    private JsonResult JsonError(string error, string errorDescription)
    {
        Response.StatusCode = 400;
        return new JsonResult(new
        {
            error,
            error_description = errorDescription
        });
    }
}