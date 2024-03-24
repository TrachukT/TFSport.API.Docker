using AutoMapper;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using TFSport.API.Filters;
using TFSport.Models.DTOModels.Users;
using TFSport.Models.Entities;
using TFSport.Models.Exceptions;
using TFSport.Services.Interfaces;

namespace TFSport.API.Controllers
{
    [ApiController]
	[Route("users")]
	[CustomExceptionFilter]

	[SwaggerResponse(400, "Bad_Request", typeof(string))]
	[SwaggerResponse(500, "Internal_Server_Error", typeof(string))]
	public class UserController : ControllerBase
	{
		private readonly IUserService _userService;

		public UserController(IUserService userService)
		{
			_userService = userService;
		}

		/// <summary>
		/// Main registration form
		/// </summary>
		/// <remarks>
		/// Sample request for registration form:
		/// <para>{</para>
		///  <para>"firstName": "Olena",</para>
		///  <para>"lastName": "Lingan",</para>
		///  <para>"email": "user@gmail.com",</para>
		///  <para>"password": "Kh0ajf81!l_",</para>
		///  <para>"repeatPassword": "Kh0ajf81!l_"</para>
		///	<para>}</para>
		/// </remarks>
		/// <param name="user"></param>
		/// <returns></returns>
		[HttpPost("register")]
		[SwaggerResponse(200, "Request_Succeeded", typeof(UserRegisterDTO))]
		public async Task<IActionResult> Register([FromBody] UserRegisterDTO user)
		{
			await _userService.RegisterUser(user);
			return Ok();
		}

		/// <summary>
		/// Pop-up window "Forgot password"
		/// </summary>
		/// <param name="email"></param>
		/// <returns></returns>
		[HttpPost("restore-password")]
		[SwaggerResponse(200, "Request_Succeeded", typeof(string))]
		public async Task<IActionResult> ForgetPassword([FromBody][EmailAddress(ErrorMessage = ErrorMessages.EmailNotValid)] string email)
		{
			await _userService.ForgotPassword(email);
			return Ok();
		}

		/// <summary>
		/// Restore password
		/// </summary>
		/// <param name="verificationToken"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		[HttpPost("recover-password")]
		[SwaggerResponse(200, "Request_Succeeded", typeof(string))]
		public async Task<IActionResult> RestorePassword([FromQuery] string verificationToken, [FromBody] RestorePasswordDTO password)
		{
			await _userService.RestorePassword(verificationToken, password.Password);
			return Ok();
		}

		[HttpPost("confirmation")]
		[SwaggerResponse(200, "Request_Succeeded", typeof(string))]
		public async Task<IActionResult> EmailVerification([FromQuery] string verificationToken)
		{
			await _userService.EmailVerification(verificationToken);
			return Ok();
		}

		/// <summary>
		/// Get all users info
		/// </summary>
		/// <returns></returns>
		[RoleAuthorization(UserRoles.SuperAdmin)]
		[HttpGet()]
		[SwaggerResponse(200, "Request_Succeeded", typeof(List<GetAllUsersDTO>))]
		public async Task<IActionResult> GetAllUsers()
		{
			var users = await _userService.GetAllUsers();
			return Ok(users);
		}

		/// <summary>
		/// Changes the role of a user based on the provided user ID and new role.
		/// </summary>
		/// <remarks>
		/// Sample request for changing user role:
		/// <code>
		/// {
		///     "newUserRole": "Author"
		/// }
		/// </code>
		/// </remarks>
		/// <param name="id">The ID of the user to change the role for.</param>
		/// <param name="request">The request object containing the new role.</param>
		/// <returns>A message indicating the result of the role change.</returns>
		[HttpPatch("{id}/role")]
		[SwaggerResponse(200, "Request_Succeeded", typeof(string))]
		[RoleAuthorization(UserRoles.SuperAdmin)]
        public async Task<IActionResult> ChangeUserRole(string id, [FromBody] ChangeUserRoleDTO request)
        {
            var newUserRole = request.NewUserRole;
            await _userService.ChangeUserRole(id, newUserRole);

            return Ok(new { Message = $"User with ID {id} has been granted a role {newUserRole}." });
        }

        /// <summary>
        /// Get info about user by user id(from auth token)
        /// </summary>
        /// <returns></returns>
        [RoleAuthorization(UserRoles.SuperAdmin, UserRoles.Author, UserRoles.User)]
		[HttpGet("info")]
		[SwaggerResponse(200, "Request_Succeeded", typeof(GetUserByIdDTO))]
		public async Task<IActionResult> GetUserById()
		{
			var userIdClaim = HttpContext.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
			var user = await _userService.GetUserById(userIdClaim.Value);

			return Ok(user);
		}

		[HttpPost("registration-confirm")]
		[SwaggerResponse(200, "Request_Succeeded", typeof(string))]
		public async Task<IActionResult> ResendEmail([FromBody][EmailAddress(ErrorMessage = ErrorMessages.EmailNotValid)]string email)
		{
			await _userService.ResendEmail(email);
			return Ok();
		}
	}
}
