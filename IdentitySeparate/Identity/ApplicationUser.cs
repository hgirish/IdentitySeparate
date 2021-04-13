using Microsoft.AspNet.Identity;

using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentitySeparate.Identity
{
    public class ApplicationUser : IUser<string>
    {
        public ApplicationUser()
        {
            Id = Guid.NewGuid().ToString();
        }

        public ApplicationUser(string userName)
            : this()
        {
            UserName = userName;
        }

        public string Id { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public virtual string PasswordHash { get; set; }
        public virtual string SecurityStamp { get; set; }
        public string PhoneNumber { get; internal set; }

        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<ApplicationUser> manager)
        {
            // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
            var userIdentity = await manager.CreateIdentityAsync(this, DefaultAuthenticationTypes.ApplicationCookie);
            // Add custom user claims here
            return userIdentity;
        }


    }
}
