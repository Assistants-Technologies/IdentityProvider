using Microsoft.AspNetCore.Identity;

namespace Infra.Modules.IdentityProvider.Data.Entities;

public class ApplicationUser : IdentityUser
{
    public string Country { get; set; } = string.Empty;
}