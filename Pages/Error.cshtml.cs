using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Infra.Modules.IdentityProvider.Pages;

public class ErrorModel : PageModel
{
    [BindProperty(SupportsGet = true)]
    public int? Code { get; set; } = 500;

    [BindProperty(SupportsGet = true)]
    public string? Message { get; set; }

    // now defined on the model:
    [BindProperty(SupportsGet = true, Name = "client_id")]
    public string? ClientId { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? Original { get; set; }

    public string SupportEmail =>
        Environment.GetEnvironmentVariable("SUPPORT_EMAIL") ?? "support@example.com";

    public void OnGet()
    {
        if (Code == 404)
        {
            Message = "The requested resource was not found. OpenID Connect is not enabled for this endpoint.";
        }
    }
}