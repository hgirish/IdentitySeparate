using IdentitySeparate.Domain.Entities;

using System.Threading;
using System.Threading.Tasks;

namespace IdentitySeparate.Domain.Repositories
{
    public interface IRoleRepository : IRepository<Role>
    {
        Role FindByName(string roleName);
        Task<Role> FindByNameAsync(string roleName);
        Task<Role> FindByNameAsync(CancellationToken cancellationToken, string roleName);
    }
}
