using JWTAuthDotNet8.Models;
using JWTAuthDotNet8.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthDotNet8.Controllers
{

   [Route("api/[controller]")]
   [ApiController]
   public class AuthController(IAuthService authService) : ControllerBase
   {

      [HttpPost("register")]
      public async Task<IActionResult> RegisterUserAsync([FromBody] UserDTO request)
      {
         var user = await authService.RegisterUserAsync(request);
         if(user is null)
         {
            return BadRequest("User Already Exists.");
         }
         return Ok(user);
      }

      [HttpPost("login")]
      public async Task<IActionResult> LoginAsync(UserDTO request)
      {
         var result = await authService.LoginAsync(request);
         if(result is null)
         {
            return Unauthorized("Invalid username or Password.");
         }
         return Ok(result);
      }
      [HttpPost("refresh-token")]
      public async Task<IActionResult> RefreshTokenAsync(RefreshTokenRequestDTO request)
      {
         var result = await authService.RefrehTokenAsync(request);
         if (result is null || result.RefreshToken is null || result.Token is null)
         {
            return Unauthorized("Invalid refresh token.");
         }
         return Ok(result);
      }
      [Authorize]
      [HttpGet("TestAuthorized")]
      public IActionResult TestAuthorized()
      {
         return Ok("You are authorized.");
      }
      [Authorize(Roles = "Admin")]
      [HttpGet("TestAdmin")]
      public IActionResult TestAdmin()
      {
         return Ok("You are an Admin.");
      }
   }
}
