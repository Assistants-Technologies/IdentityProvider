using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Infra.Modules.IdentityProvider.Data;

public class IdentityProviderDbContextFactory : IDesignTimeDbContextFactory<IdentityProviderDbContext>
{
    public IdentityProviderDbContext CreateDbContext(string[] args)
    {
        var builder = new DbContextOptionsBuilder<IdentityProviderDbContext>();

        var connString = Environment.GetEnvironmentVariable("IDP_CONNECTION_STRING")!;

        builder.UseNpgsql(connString);
        builder.UseOpenIddict();

        return new IdentityProviderDbContext(builder.Options);
    }
}