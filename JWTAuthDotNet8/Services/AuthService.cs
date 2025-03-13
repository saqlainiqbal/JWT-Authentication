using JWTAuthDotNet8.Data;
using JWTAuthDotNet8.Entity;
using JWTAuthDotNet8.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthDotNet8.Services
{
   public class AuthService(AppDbContext dbContext, IConfiguration configuration) : IAuthService
   {
      public async Task<string?> LoginAsync(UserDTO request)
      {
         var user =  await dbContext.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
         if(user is null)
         {
            return null;
         }
         if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
         {
            return null;
         }
         string token = GenerateJWTToken(user);
         return token;
      }

      public async Task<User?> RegisterUserAsync(UserDTO request)
      {
         if (await dbContext.Users.AnyAsync(u => u.Username == request.Username))
         {
            return null!;
         }
         var user = new User();
         var hashedPassword = new PasswordHasher<User>().HashPassword(user, request.Password);
         user.Username = request.Username;
         user.PasswordHash = hashedPassword;
         await dbContext.Users.AddAsync(user);
         await dbContext.SaveChangesAsync();
         return user;
      }
      private string GenerateJWTToken(User user)
      {
         var claims = new List<Claim>
         {
           new(ClaimTypes.Name, user.Username),
           new(ClaimTypes.NameIdentifier, user.Id.ToString()),
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
