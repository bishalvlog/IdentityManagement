using Microsoft.Build.ObjectModelRemoting;
using System.Security.Claims;

namespace IdentityManagement.Data
{
    public static class ClaimStore
    {
        public static List<Claim> claimslist = new List<Claim>()
        {
            new Claim("Create","Create"),
            new Claim("Edit","Edit"),
            new Claim("Delete","Delete")
        };
        
    }
}
