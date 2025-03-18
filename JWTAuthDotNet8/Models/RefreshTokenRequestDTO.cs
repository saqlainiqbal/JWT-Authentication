namespace JWTAuthDotNet8.Models
{
   public class RefreshTokenRequestDTO
   {
      public Guid userId { get; set; }
      public string refreshToken { get; set; } = string.Empty;
   }
}
