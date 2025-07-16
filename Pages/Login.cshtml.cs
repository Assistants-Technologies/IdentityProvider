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
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOpenIddictApplicationManager _apps;

    public LoginModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        IOpenIddictApplicationManager apps)
    { 
        _signInManager = signInManager;
        _userManager = userManager;
        _apps = apps;
    }

    [BindProperty]
    public InputModel Input { get; set; } = new();

    public IList<AuthenticationScheme> ExternalLogins { get; set; } = new List<AuthenticationScheme>();

    public string ReturnUrl { get; set; } = "/";

    public string? ApplicationName { get; private set; }

    [TempData]
    public string ErrorMessage { get; set; } = string.Empty;

    public class InputModel
    {
        [Required]
        public string Login { get; set; } = string.Empty;

        [Required, DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }

    public async Task OnGetAsync(string? returnUrl = null)
    {
        if (!string.IsNullOrEmpty(ErrorMessage))
            ModelState.AddModelError(string.Empty, ErrorMessage);

        ReturnUrl = returnUrl ?? Url.Content("~/");

        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
        ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

        var uri = new Uri(Request.Scheme + "://" + Request.Host + ReturnUrl);
        var qs = HttpUtility.ParseQueryString(uri.Query);
        var clientId = qs["client_id"];
        if (!string.IsNullOrEmpty(clientId))
        {
            var desc = await _apps.FindByClientIdAsync(clientId);
            if (desc != null)
                ApplicationName = await _apps.GetDisplayNameAsync(desc);
        }
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        ReturnUrl = returnUrl ?? Url.Content("~/");

        if (!ModelState.IsValid)
            return Page();

        // Znajdź użytkownika po emailu lub nazwie użytkownika
        var user = await _userManager.FindByEmailAsync(Input.Login) ?? 
                   await _userManager.FindByNameAsync(Input.Login);

        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return Page();
        }

        var result = await _signInManager.PasswordSignInAsync(
            user.UserName, 
            Input.Password, 
            Input.RememberMe, 
            lockoutOnFailure: false);

        if (result.Succeeded)
            return LocalRedirect(ReturnUrl);
        
        if (result.RequiresTwoFactor)
            return RedirectToPage("./LoginWith2fa", new { ReturnUrl, Input.RememberMe });
        
        if (result.IsLockedOut)
            return RedirectToPage("./Lockout");

        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
        return Page();
    }
}