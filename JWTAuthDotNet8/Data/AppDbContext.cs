using JWTAuthDotNet8.Entity;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthDotNet8.Data
{
   public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
   {
      public DbSet<User> Users { get; set; }
   }
}
