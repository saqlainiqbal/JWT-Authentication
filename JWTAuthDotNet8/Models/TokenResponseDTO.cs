namespace JWTAuthDotNet8.Models
{
   public class TokenResponseDTO
   {
      public required string Token { get; set; } = string.Empty;
      public required string RefreshToken { get; set; } = string.Empty;
   }
}
