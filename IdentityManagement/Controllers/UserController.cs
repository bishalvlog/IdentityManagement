using IdentityManagement.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManagement.Controllers
{
    public class UserController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly UserManager<IdentityUser> _userManager;

        public UserController(ApplicationDbContext dbContext, UserManager<IdentityUser> userManager)
        {
            _db = dbContext;
        }
        public IActionResult Index()
        {
           var userlist =_db.applicationUsers.ToList();
            var userRole =_db.UserRoles.ToList();
            var Role =_db.Roles.ToList();
            foreach (var user in userlist)
            {
                var roles = userRole.FirstOrDefault(u=>u.UserId == user.Id);    
                if(roles == null)
                {
                    user.Role = "nonRole";

                }
                else
                {
                    user.Role = Role.FirstOrDefault(u => u.Id == roles.RoleId).Name;
                }
                return View(userlist);
            }
        }
    }
}
