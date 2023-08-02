namespace IdentityManagement.Models.ViewModel
{
    public class TwoFactorAuthenicationVm
    {
        public string Code { get; set; }    
        public string Token { get; set; }   
        public string QRCodeUrl { get; set; }

    }
}
