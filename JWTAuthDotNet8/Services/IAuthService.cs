using JWTAuthDotNet8.Entity;
using JWTAuthDotNet8.Models;

namespace JWTAuthDotNet8.Services
{
   public interface IAuthService
   {
      Task<User?> RegisterUserAsync(UserDTO user);
      Task<string?> LoginAsync(UserDTO user);

   }
}
