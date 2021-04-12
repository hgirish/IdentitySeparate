using IdentitySeparate.Domain.Entities;
using IdentitySeparate.Domain.Repositories;

using System.Data.Entity;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace IdentitySeparate.Data.EntityFramework.Repositories
{
    internal class UserRepository : Repository<User>, IUserRepository
    {
        internal UserRepository(ApplicationDbContext context)
            : base(context)
        {
        }

        public User FindByEmail(string email)
        {
            throw new System.NotImplementedException();
        }

        public Task<User> FindByEmailAsync(string email)
        {
            throw new System.NotImplementedException();
        }

        public Task<User> FindByEmailAsync(CancellationToken cancellationToken, string email)
        {
            throw new System.NotImplementedException();
        }

        public User FindByUserName(string username)
        {
            return Set.FirstOrDefault(x => x.UserName == username);
        }

        public Task<User> FindByUserNameAsync(string username)
        {
            return Set.FirstOrDefaultAsync(x => x.UserName == username);
        }

        public Task<User> FindByUserNameAsync(System.Threading.CancellationToken cancellationToken, string username)
        {
            return Set.FirstOrDefaultAsync(x => x.UserName == username, cancellationToken);
        }
    }
}
