using JWTAuthDotNet8.Entity;
using JWTAuthDotNet8.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthDotNet8.Controllers
{

   [Route("api/[controller]")]
   [ApiController]
   public class AuthController(IConfiguration configuration) : ControllerBase
   {
      private static readonly User user = new();

      [HttpPost("register")]
      public IActionResult RegisterUser([FromBody] UserDTO request)
      {
         var hashedPassword = new PasswordHasher<User>().HashPassword(user, request.Password);
         user.Username = request.Username;
         user.PasswordHash = hashedPassword;
         return Ok(user);
      }

      [HttpPost("login")]
      public IActionResult Login(UserDTO request)
      {
         if (user.Username != request.Username) 
         {
            return BadRequest("User Not Found.");
         }
         if(new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
         {
            return BadRequest("Password Incorrect");
         }
         string token = GenerateJWTToken(user);
         return Ok(token);
      }

      private string GenerateJWTToken(User user)
      {
        var claims  = new List<Claim>
        {
           new(ClaimTypes.Name, user.Username),
           new(ClaimTypes.Role, user.Role)
        };
         var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!));
         var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
         var token = new JwtSecurityToken(
            issuer: configuration.GetValue<string>("AppSettings:Issuer"),
            audience: configuration.GetValue<string>("AppSettings:Audience"),
            claims: claims,
            expires: DateTime.Now.AddMinutes(30),
            signingCredentials: creds
         );
         return new JwtSecurityTokenHandler().WriteToken(token);
      }
   }
}
