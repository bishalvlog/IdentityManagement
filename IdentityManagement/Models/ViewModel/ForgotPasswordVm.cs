using System.ComponentModel.DataAnnotations;

namespace IdentityManagement.Models.ViewModel
{
    public class ForgotPasswordVm
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
