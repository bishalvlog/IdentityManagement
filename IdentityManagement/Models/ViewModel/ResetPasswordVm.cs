using System.ComponentModel.DataAnnotations;

namespace IdentityManagement.Models.ViewModel
{
    public class ResetPasswordVm
    {
        [Required]
        [EmailAddress]
        [Display(Name ="Email")]
        public string Email { get; set; }
        [Required]
        [StringLength(100,ErrorMessage ="The {0} must be at Least {2} Character long",MinimumLength =6)]
        [DataType(DataType.Password)]
        [Display(Name ="Password")]
        public string Password { get; set; }
        [DataType(DataType.Password)]
        [Display (Name ="confirm Password")]
        public string ConfirmPassword { get; set; }
        [Required]
        public string Code { get; set; }    
    }
}
