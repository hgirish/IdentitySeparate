using Microsoft.AspNet.Identity;

using System;

namespace IdentitySeparate.Identity
{
    public class IdentityUser : IUser<Guid>
    {
        public IdentityUser()
        {
            Id = Guid.NewGuid();
        }

        public IdentityUser(string userName)
            : this()
        {
            UserName = userName;
        }

        public Guid Id { get; set; }
        public string UserName { get; set; }
        public virtual string PasswordHash { get; set; }
        public virtual string SecurityStamp { get; set; }
    }
}
