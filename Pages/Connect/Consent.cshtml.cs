using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Server.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Infra.Modules.IdentityProvider.Data.Entities;
using OpenIddict.Abstractions;

namespace Infra.Modules.IdentityProvider.Pages.Connect;

public class ConsentModel : PageModel
{
    private readonly UserManager<ApplicationUser>          _users;
    private readonly IOpenIddictApplicationManager         _appManager;

    public ConsentModel(UserManager<ApplicationUser> users,
                        IOpenIddictApplicationManager appManager)
    {
        _users      = users;
        _appManager = appManager;
    }

    [BindProperty] 
    public string? Submit { get; set; }

    public IReadOnlyList<string> Scopes           { get; private set; } = Array.Empty<string>();
    public string               ClientDisplayName{ get; private set; } = "";
    public string               PromptText       { get; private set; } = "";
    public string               ReturnUrl        { get; private set; } = "/connect/authorize";

    public async Task<IActionResult> OnGetAsync()
    {
        var clientId = HttpContext.Session.GetString("oidc_client_id")
                       ?? throw new InvalidOperationException("Missing consent context.");
        var scopeRaw = HttpContext.Session.GetString("oidc_scope")
                       ?? throw new InvalidOperationException("Missing consent context.");
        ReturnUrl = HttpContext.Session.GetString("return_url") ?? ReturnUrl;

        // Split out the scopes to show
        Scopes = scopeRaw
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);

        // Look up the display name
        var app = await _appManager.FindByClientIdAsync(clientId);
        ClientDisplayName = (await _appManager.GetDisplayNameAsync(app)) ?? clientId;

        // Has the user already granted *any* scopes for this client?
        var user         = await _users.GetUserAsync(User)
                         ?? throw new InvalidOperationException("Unknown user.");
        var claimType    = $"consent:{clientId}";
        var existingClaim= (await _users.GetClaimsAsync(user))
                           .FirstOrDefault(c => c.Type == claimType);

        // Decide which prompt to show
        PromptText = existingClaim == null
            ? "is requesting access to your account."
            : "is requesting additional permissions.";

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var clientId  = HttpContext.Session.GetString("oidc_client_id")!;
        var newScopes = HttpContext.Session.GetString("oidc_scope")!
                            .Split(' ', StringSplitOptions.RemoveEmptyEntries);

        var user      = await _users.GetUserAsync(User)
                         ?? throw new InvalidOperationException("Unknown user.");
        var claimType = $"consent:{clientId}";
        var existingClaim = (await _users.GetClaimsAsync(user))
                             .FirstOrDefault(c => c.Type == claimType);

        // Merge old + new
        var all = new HashSet<string>(
            existingClaim?.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries)
              ?? Array.Empty<string>(),
            StringComparer.Ordinal);
        foreach (var s in newScopes) all.Add(s);

        // Update the claim store
        if (existingClaim != null)
            await _users.RemoveClaimAsync(user, existingClaim);

        await _users.AddClaimAsync(user, new Claim(claimType, string.Join(' ', all)));

        return Submit == "accept"
            ? Redirect(ReturnUrl)
            : Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}