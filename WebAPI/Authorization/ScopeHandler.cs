using Microsoft.AspNetCore.Authorization;
using System.Linq;
using System.Threading.Tasks;

namespace WebAPI
{
    public class ScopeHandler : AuthorizationHandler<ScopeRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ScopeRequirement requirement)
        {
            //Just for checking
            var claims = context.User.Claims.ToList();

            //we need the scope claim. If not do nothing
            if (!context.User.HasClaim(c => c.Type == "http://schemas.microsoft.com/identity/claims/scope" && c.Issuer == requirement.Issuer))
                return Task.CompletedTask;

            //split the scopes (we can have several)
            var scopes = context.User.FindFirst(c => c.Type == "http://schemas.microsoft.com/identity/claims/scope" && c.Issuer == requirement.Issuer).Value.Split(' ');

            //check if we have the right scope for the action
            if (scopes.Any(s => s == requirement.Scope))
                context.Succeed(requirement);

            //if not do nothing
            return Task.CompletedTask;
        }
    }
}
