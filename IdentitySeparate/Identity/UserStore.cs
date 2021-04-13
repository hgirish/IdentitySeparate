using IdentitySeparate.Domain;

using Microsoft.AspNet.Identity;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentitySeparate.Identity
{
    public class UserStore : IUserLoginStore<ApplicationUser>,
        IUserClaimStore<ApplicationUser>,
        IUserRoleStore<ApplicationUser>,
        IUserPasswordStore<ApplicationUser>,
        IUserSecurityStampStore<ApplicationUser>,
        IUserStore<ApplicationUser>,
        IDisposable
    {
        private readonly IUnitOfWork _unitOfWork;

        public UserStore(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        public Task AddClaimAsync(ApplicationUser user, Claim claim)
        {
            if (user == null)
                throw new ArgumentNullException("user");
            if (claim == null)
                throw new ArgumentNullException("claim");

            var u = _unitOfWork.UserRepository.FindById(user.Id);
            if (u == null)
                throw new ArgumentException("IdentityUser does not correspond to a User entity.", "user");

            var c = new Domain.Entities.Claim
            {
                ClaimType = claim.Type,
                ClaimValue = claim.Value,
                User = u
            };
            u.Claims.Add(c);

            _unitOfWork.UserRepository.Update(u);
            return _unitOfWork.SaveChangesAsync();
        }

        public Task AddLoginAsync(ApplicationUser user, UserLoginInfo login)
        {
            if (user == null)
                throw new ArgumentNullException("user");
            if (login == null)
                throw new ArgumentNullException("login");

            var u = _unitOfWork.UserRepository.FindById(user.Id);
            if (u == null)
                throw new ArgumentException("IdentityUser does not correspond to a User entity.", "user");

            var l = new Domain.Entities.ExternalLogin
            {
                LoginProvider = login.LoginProvider,
                ProviderKey = login.ProviderKey,
                User = u
            };
            u.Logins.Add(l);

            _unitOfWork.UserRepository.Update(u);
            return _unitOfWork.SaveChangesAsync();
        }

        public Task AddToRoleAsync(ApplicationUser user, string roleName)
        {
            if (user == null)
                throw new ArgumentNullException("user");
            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentException("Argument cannot be null, empty, or whitespace: roleName.");

            var u = _unitOfWork.UserRepository.FindById(user.Id);
            if (u == null)
                throw new ArgumentException("IdentityUser does not correspond to a User entity.", "user");
            var r = _unitOfWork.RoleRepository.FindByName(roleName);
            if (r == null)
                throw new ArgumentException("roleName does not correspond to a Role entity.", "roleName");

            u.Roles.Add(r);
            _unitOfWork.UserRepository.Update(u);

            return _unitOfWork.SaveChangesAsync();
        }

        public async Task CreateAsync(ApplicationUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            var u = getUser(user);
            _unitOfWork.UserRepository.Add(u);
             await _unitOfWork.SaveChangesAsync();
        }

        
        public async Task DeleteAsync(ApplicationUser user)
        {
            if (user == null)
                throw new ArgumentNullException("user");

            var u = getUser(user);

            _unitOfWork.UserRepository.Remove(u);
            await _unitOfWork.SaveChangesAsync();
        }

        public void Dispose()
        {
            // Dispose does nothing since we want Unity to manage the lifecycle of our Unit of Work
        }

        public Task<ApplicationUser> FindAsync(UserLoginInfo login)
        {
            if (login == null)
                throw new ArgumentNullException("login");

            var identityUser = default(ApplicationUser);

            var l = _unitOfWork.ExternalLoginRepository.GetByProviderAndKey(login.LoginProvider, login.ProviderKey);
            if (l != null)
                identityUser = getIdentityUser(l.User);

            return Task.FromResult<ApplicationUser>(identityUser);
        }

        public Task<ApplicationUser> FindByIdAsync(string userId)
        {
            var user = _unitOfWork.UserRepository.FindById(userId);
            return Task.FromResult<ApplicationUser>(getIdentityUser(user));
        }

        public Task<ApplicationUser> FindByNameAsync(string userName)
        {
            var user = _unitOfWork.UserRepository.FindByUserName(userName);
            return Task.FromResult<ApplicationUser>(getIdentityUser(user));
        }

        public Task<IList<Claim>> GetClaimsAsync(ApplicationUser user)
        {
            if (user == null)
                throw new ArgumentNullException("user");

            var u = _unitOfWork.UserRepository.FindById(user.Id);
            if (u == null)
                throw new ArgumentException("IdentityUser does not correspond to a User entity.", "user");

            return Task.FromResult<IList<Claim>>(u.Claims.Select(x => new Claim(x.ClaimType, x.ClaimValue)).ToList());
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(ApplicationUser user)
        {
            if (user == null)
                throw new ArgumentNullException("user");

            var u = _unitOfWork.UserRepository.FindById(user.Id);
            if (u == null)
                throw new ArgumentException("IdentityUser does not correspond to a User entity.", "user");

            return Task.FromResult<IList<UserLoginInfo>>(u.Logins.Select(x => new UserLoginInfo(x.LoginProvider, x.ProviderKey)).ToList());
        }

        public Task<string> GetPasswordHashAsync(ApplicationUser user)
        {
            if (user == null)
                throw new ArgumentNullException("user");
            return Task.FromResult<string>(user.PasswordHash);
        }

        public Task<IList<string>> GetRolesAsync(ApplicationUser user)
        {
            if (user == null)
                throw new ArgumentNullException("user");

            var u = _unitOfWork.UserRepository.FindById(user.Id);
            if (u == null)
                throw new ArgumentException("IdentityUser does not correspond to a User entity.", "user");

            return Task.FromResult<IList<string>>(u.Roles.Select(x => x.Name).ToList());
        }

        public Task<string> GetSecurityStampAsync(ApplicationUser user)
        {
            if (user == null)
                throw new ArgumentNullException("user");
            return Task.FromResult<string>(user.SecurityStamp);
        }

        public Task<bool> HasPasswordAsync(ApplicationUser user)
        {
            if (user == null)
                throw new ArgumentNullException("user");
            return Task.FromResult<bool>(!string.IsNullOrWhiteSpace(user.PasswordHash));
        }

        public Task<bool> IsInRoleAsync(ApplicationUser user, string roleName)
        {
            if (user == null)
                throw new ArgumentNullException("user");
            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentException("Argument cannot be null, empty, or whitespace: role.");

            var u = _unitOfWork.UserRepository.FindById(user.Id);
            if (u == null)
                throw new ArgumentException("IdentityUser does not correspond to a User entity.", "user");

            return Task.FromResult<bool>(u.Roles.Any(x => x.Name == roleName));
        }

        public Task RemoveClaimAsync(ApplicationUser user, Claim claim)
        {
            if (user == null)
                throw new ArgumentNullException("user");
            if (claim == null)
                throw new ArgumentNullException("claim");

            var u = _unitOfWork.UserRepository.FindById(user.Id);
            if (u == null)
                throw new ArgumentException("IdentityUser does not correspond to a User entity.", "user");

            var c = u.Claims.FirstOrDefault(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value);
            u.Claims.Remove(c);

            _unitOfWork.UserRepository.Update(u);
            return _unitOfWork.SaveChangesAsync();
        }

        public Task RemoveFromRoleAsync(ApplicationUser user, string roleName)
        {
            if (user == null)
                throw new ArgumentNullException("user");
            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentException("Argument cannot be null, empty, or whitespace: role.");

            var u = _unitOfWork.UserRepository.FindById(user.Id);
            if (u == null)
                throw new ArgumentException("IdentityUser does not correspond to a User entity.", "user");

            var r = u.Roles.FirstOrDefault(x => x.Name == roleName);
            u.Roles.Remove(r);

            _unitOfWork.UserRepository.Update(u);
            return _unitOfWork.SaveChangesAsync();
        }

        public Task RemoveLoginAsync(ApplicationUser user, UserLoginInfo login)
        {
            if (user == null)
                throw new ArgumentNullException("user");
            if (login == null)
                throw new ArgumentNullException("login");

            var u = _unitOfWork.UserRepository.FindById(user.Id);
            if (u == null)
                throw new ArgumentException("IdentityUser does not correspond to a User entity.", "user");

            var l = u.Logins.FirstOrDefault(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey);
            u.Logins.Remove(l);

            _unitOfWork.UserRepository.Update(u);
            return _unitOfWork.SaveChangesAsync();
        }

        public Task SetPasswordHashAsync(ApplicationUser user, string passwordHash)
        {
            user.PasswordHash = passwordHash;
            return Task.FromResult(0);
        }

        public Task SetSecurityStampAsync(ApplicationUser user, string stamp)
        {
            user.SecurityStamp = stamp;
            return Task.FromResult(0);
        }

        public async Task UpdateAsync(ApplicationUser user)
        {

            if (user == null)
                throw new ArgumentException("user");

            var u = _unitOfWork.UserRepository.FindById(user.Id);
            if (u == null)
                throw new ArgumentException("IdentityUser does not correspond to a User entity.", "user");

            populateUser(u, user);

            _unitOfWork.UserRepository.Update(u);
            await _unitOfWork.SaveChangesAsync();
        }

        private Domain.Entities.User getUser(ApplicationUser identityUser)
        {
            if (identityUser == null)
            {
                return null;
            }
            var user = new Domain.Entities.User();
            populateUser(user, identityUser);
            return user;
        }
        private void populateUser(Domain.Entities.User user, ApplicationUser identityUser)
        {
            user.UserId = identityUser.Id;
            user.UserName = identityUser.UserName;
            user.PasswordHash = identityUser.PasswordHash;
            user.SecurityStamp = identityUser.SecurityStamp;
        }

        private ApplicationUser getIdentityUser(Domain.Entities.User user)
        {
            if (user == null)
            {
                return null;
            }
            var identityUser = new ApplicationUser();
            populateIdentityUser(identityUser, user);
            return identityUser;
        }
        private void populateIdentityUser(ApplicationUser identityUser, Domain.Entities.User user)
        {
            identityUser.Id = user.UserId;
            identityUser.UserName = user.UserName;
            identityUser.PasswordHash = user.PasswordHash;
            identityUser.SecurityStamp = user.SecurityStamp;
        }
    }
}
