using IdentitySeparate.Data.EntityFramework.Configuration;
using IdentitySeparate.Domain.Entities;

using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Threading.Tasks;

namespace IdentitySeparate.Data.EntityFramework
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(string nameOrConnectionString)
            : base(nameOrConnectionString)
        {
        }

        internal IDbSet<User> Users { get; set; }
        internal IDbSet<Role> Roles { get; set; }
        internal IDbSet<ExternalLogin> Logins { get; set; }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            modelBuilder.Configurations.Add(new UserConfiguration());
            modelBuilder.Configurations.Add(new RoleConfiguration());
            modelBuilder.Configurations.Add(new ExternalLoginConfiguration());
            modelBuilder.Configurations.Add(new ClaimConfiguration());
        }
    }

    public class ApplicationDbContextFactory : IDbContextFactory<ApplicationDbContext>
    {
        public ApplicationDbContext Create()
        {
            return new ApplicationDbContext("IdentitySeparate");
        }
    }


}

