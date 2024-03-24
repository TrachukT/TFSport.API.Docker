using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;
using TFSport.API.Filters;
using TFSport.Models.DTOModels;
using TFSport.Models.DTOModels.Users;
using TFSport.Services.Interfaces;

namespace TFSport.API.Controllers
{
    [ApiController]
	[Route("token")]
    [CustomExceptionFilter]

    [SwaggerResponse(200, "Request_Succeeded", typeof(string))]
	[SwaggerResponse(400, "Bad_Request", typeof(string))]
	[SwaggerResponse(500, "Internal_Server_Error", typeof(string))]
	public class TokenController : ControllerBase
	{
		private readonly IUserService _userService;
		private readonly IJWTService _jwtService;
		public TokenController(IUserService userService, IJWTService jwtService)
		{
			_userService = userService;
			_jwtService = jwtService;
		}

		/// <summary>
		/// Generates a new access token based on the provided user login credentials.
		/// </summary>
		/// <remarks>
		/// Sample request for generating an access token:
		/// <code>
		/// {
		///     "email": "user@gmail.com",
		///     "password": "Kh0ajf81!l_"
		/// }
		/// </code>
		/// </remarks>
		/// <param name="model">The user's login credentials.</param>
		/// <returns>A new access token and refresh token.</returns>
		[HttpPost]
        public async Task<IActionResult> GetTokens([FromBody] UserLoginDTO model)
		{
            var email = model.Email.ToLower();

            var id = await _userService.ValidateCredentialsAsync(email, model.Password);

            var accessToken = await _jwtService.GenerateAccessTokenAsync(email, id);

            var refreshToken = await _jwtService.GenerateRefreshTokenAsync(email, id);

            return Ok(new
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            });
        }

		/// <summary>
		/// Generates a new access token using a refresh token.
		/// </summary>
		/// <remarks>
		/// Sample request for refreshing an access token:
		/// <code>
		/// {
		///     "refreshToken": "your-refresh-token"
		/// }
		/// </code>
		/// </remarks>
		/// <param name="model">The refresh token.</param>
		/// <returns>A new access token and refresh token.</returns>
		[HttpPost("refresh")]
		[Authorize]
        public async Task<IActionResult> RefreshTokens([FromBody] RefreshRequestModel model)
		{
			var refreshToken = model.RefreshToken;

            var storedEmail = await _jwtService.GetEmailFromToken(refreshToken);
            var storedId = await _jwtService.GetIdFromToken(refreshToken);

            var newAccessToken = await _jwtService.GenerateAccessTokenAsync(storedEmail, storedId);
            var newRefreshToken = await _jwtService.GenerateRefreshTokenAsync(storedEmail, storedId);

            return Ok(new
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }
	}
}
