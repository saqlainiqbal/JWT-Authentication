using JWTAuthDotNet8.Models;
using JWTAuthDotNet8.Services;
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
         var token = await authService.LoginAsync(request);
         if(token is null)
         {
            return Unauthorized("Invalid Credentials.");
         }
         return Ok(token);
      }
   }
}
