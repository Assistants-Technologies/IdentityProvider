using System.ComponentModel.DataAnnotations;
using System.Web;
using Infra.Modules.IdentityProvider.Data.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace Infra.Modules.IdentityProvider.Pages;

public class LoginModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IOpenIddictApplicationManager _apps;

    public LoginModel(SignInManager<ApplicationUser> signInManager,
                      IOpenIddictApplicationManager apps)
    { 
        _signInManager = signInManager;
        _apps = apps;
    }

    [BindProperty]
    public InputModel Input { get; set; }

    public IList<AuthenticationScheme> ExternalLogins { get; set; }

    public string ReturnUrl { get; set; }

    public string? ApplicationName { get; private set; }

    [TempData]
    public string ErrorMessage { get; set; }

    public class InputModel
    {
        [Required, EmailAddress]
        public string Email { get; set; }

        [Required, DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }

    public async Task OnGetAsync(string returnUrl = null)
    {
        ReturnUrl = returnUrl ?? Url.Content("~/");
        if (!string.IsNullOrEmpty(ErrorMessage))
            ModelState.AddModelError("", ErrorMessage);

        // Sign out any external cookie
        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
        ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

        // Extract client_id from the returnUrl query
        var uri = new Uri(Request.Scheme + "://" + Request.Host + ReturnUrl);
        var qs = HttpUtility.ParseQueryString(uri.Query);
        var clientId = qs["client_id"];
        if (!string.IsNullOrEmpty(clientId))
        {
            var descriptor = await _apps.FindByClientIdAsync(clientId);
            if (descriptor != null)
                ApplicationName = await _apps.GetDisplayNameAsync(descriptor);
        }
    }

    public async Task<IActionResult> OnPostAsync(string returnUrl = null)
    {
        ReturnUrl = returnUrl ?? Url.Content("~/");
        ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

        if (!ModelState.IsValid)
            return Page();

        var result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe, false);
        if (result.Succeeded)
            return LocalRedirect(ReturnUrl);
        if (result.RequiresTwoFactor)
            return RedirectToPage("./LoginWith2fa", new { ReturnUrl, RememberMe = Input.RememberMe });
        if (result.IsLockedOut)
            return RedirectToPage("./Lockout");

        ModelState.AddModelError("", "Invalid login attempt.");
        return Page();
    }
}