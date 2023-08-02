using System.ComponentModel.DataAnnotations;

namespace IdentityManagement.Models.ViewModel
{
    public class VerifyAuthenticatorVm
    {
        [Required]
        public string Code { get; set; }    
        public string ReturnUrl { get; set; }
        [Display (Name ="Remember me?")]
        public bool RememberMe { get; set; }


    }
}
