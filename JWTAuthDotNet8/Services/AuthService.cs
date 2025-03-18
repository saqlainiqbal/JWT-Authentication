using JWTAuthDotNet8.Data;
using JWTAuthDotNet8.Entity;
using JWTAuthDotNet8.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTAuthDotNet8.Services
{
   public class AuthService(AppDbContext dbContext, IConfiguration configuration) : IAuthService
   {
      public async Task<TokenResponseDTO?> LoginAsync(UserDTO request)
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
         var response = new TokenResponseDTO
         {
            Token = token,
            RefreshToken = await GenrateAndSaveRefreshTokenAsync(user)
         };
         return response;
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

      private async Task<User?> ValidateRefreshTokenAsync(Guid userId , string refreshToken)
      {
         var user = await dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
         if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
         {
            return null;
         }
         return user;

      }
      private static string GenrateRefreshToken()
      {
         var randomNumber = new byte[32];
         using var rng = RandomNumberGenerator.Create();
         rng.GetBytes(randomNumber);
         return Convert.ToBase64String(randomNumber);
      }
      private async Task<string> GenrateAndSaveRefreshTokenAsync(User user)
      {
         var refreshToken = GenrateRefreshToken();
         user.RefreshToken = refreshToken;
         user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);
         await dbContext.SaveChangesAsync();
         return refreshToken;
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

      public async Task<TokenResponseDTO?> RefrehTokenAsync(RefreshTokenRequestDTO refreshToken)
      {
         var user = await ValidateRefreshTokenAsync(refreshToken.userId, refreshToken.refreshToken);
         if (user is null)
         {
            return null;
         }
         var response = new TokenResponseDTO
         {
            Token = GenerateJWTToken(user),
            RefreshToken = await GenrateAndSaveRefreshTokenAsync(user)
         };
         return response;
      }
   }
}
