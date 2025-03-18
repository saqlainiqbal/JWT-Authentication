using JWTAuthDotNet8.Entity;
using JWTAuthDotNet8.Models;

namespace JWTAuthDotNet8.Services
{
   public interface IAuthService
   {
      Task<User?> RegisterUserAsync(UserDTO user);
      Task<TokenResponseDTO?> LoginAsync(UserDTO user);
      Task<TokenResponseDTO?> RefrehTokenAsync(RefreshTokenRequestDTO refreshToken);
   }
}
