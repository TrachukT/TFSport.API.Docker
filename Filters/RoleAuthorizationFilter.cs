using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using TFSport.Models.Entities;
using TFSport.Services.Interfaces;

namespace TFSport.API.Filters
{
    public class RoleAuthorizationFilter : IAsyncAuthorizationFilter
	{
		private readonly string[] _acceptedRoles;

		public RoleAuthorizationFilter(params UserRoles[] acceptedRoles)
		{
			_acceptedRoles = acceptedRoles.Select(role => role.ToString()).ToArray();
		}

		public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
		{
			var userService = context.HttpContext.RequestServices.GetRequiredService<IUserService>();

			var user = context.HttpContext.User;
			if (!user.Identity.IsAuthenticated)
			{
				context.Result = new UnauthorizedResult();
				return;
			}

			var emailClaim = user.FindFirstValue(ClaimTypes.Email);
			if (string.IsNullOrEmpty(emailClaim))
			{
				context.Result = new UnauthorizedResult();
				return;
			}

			var userRoles = await userService.GetUserRolesByEmailAsync(emailClaim);

			if (!_acceptedRoles.Any(role => userRoles.Contains(Enum.Parse<UserRoles>(role))))
			{
				context.Result = new ForbidResult();
			}
		}
	}
}