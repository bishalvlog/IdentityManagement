using System.ComponentModel.DataAnnotations;

namespace IdentityManagement.Models.ViewModel
{
    public class ExternalLoginConfirmationVm
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        public string Name { get; set; }    

    }
}
