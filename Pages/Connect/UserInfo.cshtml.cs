using System.Security.Claims;
using Infra.Modules.IdentityProvider.Data.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace Infra.Modules.IdentityProvider.Pages.Connect;
 
[IgnoreAntiforgeryToken]
[Produces("application/json")]
public class UserInfoModel : PageModel
{
    private readonly UserManager<ApplicationUser> _userManager;

    public UserInfoModel(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    [HttpGet]
    [HttpPost]
    public async Task<IActionResult> OnGet()
    {
        Console.WriteLine("UserInfo endpoint calleddddddddddddddddddddd.");
        try
        {
            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            
            if (!result.Succeeded || result.Principal == null)
            {
                return JsonError(OpenIddictConstants.Errors.InvalidToken, 
                    "The access token is invalid.");
            }

            var userId = result.Principal.FindFirst(OpenIddictConstants.Claims.Subject)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return JsonError(OpenIddictConstants.Errors.InvalidToken,
                    "The subject claim is missing.");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return JsonError(OpenIddictConstants.Errors.InvalidToken,
                    "The user account no longer exists.");
            }

            var claims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [OpenIddictConstants.Claims.Subject] = userId
            };

            if (result.Principal.HasScope(OpenIddictConstants.Scopes.Email))
            {
                claims[OpenIddictConstants.Claims.Email] = user.Email ?? string.Empty;
                claims[OpenIddictConstants.Claims.EmailVerified] = await _userManager.IsEmailConfirmedAsync(user);
            }

            if (result.Principal.HasScope(OpenIddictConstants.Scopes.Profile))
            {
                claims[OpenIddictConstants.Claims.Name] = user.UserName ?? string.Empty;
                claims[OpenIddictConstants.Claims.PreferredUsername] = user.UserName ?? string.Empty;
                claims["country"] = user.Country ?? string.Empty;
            }

            Response.ContentType = "application/json";
            return new JsonResult(claims);
        }
        catch (Exception ex)
        {
            return JsonError(OpenIddictConstants.Errors.ServerError,
                $"An unexpected error occurred: {ex.Message}");
        }
    }

    private IActionResult JsonError(string error, string description)
    {
        Response.ContentType = "application/json";
        return new JsonResult(new
        {
            error,
            error_description = description
        });
    }
}