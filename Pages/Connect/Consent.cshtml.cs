using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Server.AspNetCore;

namespace Infra.Modules.IdentityProvider.Pages.Connect;

public class ConsentModel : PageModel
{
    [BindProperty]
    public string? Submit { get; set; }

    public List<string> Scopes { get; private set; } = new();

    public IActionResult OnGet()
    {
        // Pobieramy dane z sesji
        var scopesRaw = HttpContext.Session.GetString("oidc_scope");
        if (string.IsNullOrEmpty(scopesRaw))
        {
            return BadRequest("Brak kontekstu zgody.");
        }

        Scopes = scopesRaw.Split(' ').ToList();
        return Page();
    }

    public IActionResult OnPost()
    {
        if (Submit == "accept")
        {
            HttpContext.Session.SetString("consent", "yes");
            return Redirect(HttpContext.Session.GetString("return_url") ?? "/connect/authorize");
        }

        // jak kliknie "Anuluj" – kończymy flow
        return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}