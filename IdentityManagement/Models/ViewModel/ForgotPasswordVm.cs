using System.ComponentModel.DataAnnotations;

namespace IdentityManagement.Models.ViewModel
{
    public class ForgotPasswordVm
    {
        [Required]
        [EmailAddress]
        [Display(Name = "Register Your Email")]
        public string Email { get; set; }
        public bool EmailSent { get; set; } 

    }
}
