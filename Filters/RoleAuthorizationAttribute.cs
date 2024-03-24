using Microsoft.AspNetCore.Mvc;
using TFSport.Models.Entities;

namespace TFSport.API.Filters
{
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
	public class RoleAuthorizationAttribute : TypeFilterAttribute
	{
		public RoleAuthorizationAttribute(params UserRoles[] acceptedRoles)
			: base(typeof(RoleAuthorizationFilter))
		{
			Arguments = new object[] { acceptedRoles };
		}
	}
}