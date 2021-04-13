using System;

namespace IdentitySeparate.Extensions
{
    public static  class StringExtensions
    {
        public static  Guid ToGuid(this string value)
        {
            Guid result;
            Guid.TryParse(value, out result);
            return result;
        }
    }
}