using Microsoft.AspNetCore.Mvc;

namespace IdentityManagement.Controllers
{
    public class UserController1 : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
