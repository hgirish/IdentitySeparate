using System;
using System.ComponentModel.DataAnnotations.Schema;

namespace IdentitySeparate.Domain.Entities
{
    public class ExternalLogin
    {
        private User _user;

        #region Scalar Properties
        public virtual string LoginProvider { get; set; }
        public virtual string ProviderKey { get; set; }
        //[Column("UserId", TypeName = "UniqueIdentifier")]
        public virtual string UserId { get; set; } = Guid.NewGuid().ToString();
        #endregion

        #region Navigation Properties
        public virtual User User
        {
            get { return _user; }
            set
            {
                _user = value;
                UserId = value.UserId;
            }
        }
        #endregion
    }
}
