using IdentityManagement.Data;
using IdentityManagement.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.CSharp.Syntax;

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
            return View(userlist);
        }
        [HttpGet]
        public IActionResult Edit(string userId)
        {
            var objform = _db.applicationUsers.FirstOrDefault(u=>u.Id==userId);
            if(objform == null)
            {
                return NotFound();
            }
            var userRole = _db.UserRoles.ToList();
            var Roles= _db.Roles.ToList();
            var role =userRole.FirstOrDefault(u=>u.UserId==userId);
                if (Roles != null)
                {
                objform.RoleId = Roles.FirstOrDefault(u => u.Id == role.RoleId).Id;

                }
            objform.RoleList = _db.Roles.Select(u => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
            {
                Text = u.Name,
                Value = u.Id
            });
            return View(objform);
    
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(ApplicationUser user)
        {
            if (!ModelState.IsValid)
            {

                var objform = _db.applicationUsers.FirstOrDefault(u => u.Id == user.Id);
                if (objform == null)
                {
                    return NotFound();
                }
                //var userRole = _db.UserRoles.ToList();
                //var Roles = _db.Roles.ToList();
                var UserRole = _db.UserRoles.FirstOrDefault(u => u.UserId == objform.Id);
                if (UserRole != null)
                {
                    var previousRoleName = _db.Roles.Where(u => u.Id == UserRole.RoleId).Select(e => e.Name).FirstOrDefault();
                    //remove the old age
                    await _userManager.RemoveFromRoleAsync(objform, previousRoleName);

                }
                //add role
                await _userManager.AddToRoleAsync(objform, _db.Roles.FirstOrDefault(u => u.Id == user.RoleId).Name);
                objform.Name = user.Name;
                _db.SaveChanges();
                TempData[SD.Success] = "user has been edited successfully";
                return RedirectToAction(nameof(Index));
            }
            user.RoleList =_db.Roles.Select(u => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem
            {
               Text =u.Name,
               Value=u.Id

            });
            return View(user);

        }
        [HttpPost]
        public IActionResult LockUnlock (string userId)
        {
            var objfrom =_db.applicationUsers.FirstOrDefault(u=>u.Id == userId);
            if(objfrom != null)
            {
                return NotFound();
            }
            if(objfrom.LockoutEnd != null && objfrom.LockoutEnd > DateTime.Now)
            {
                objfrom.LockoutEnd = DateTime.Now;
                TempData[SD.Success] = "user  unlock successfully";
            }
            else
            {
                objfrom.LockoutEnd = DateTime.Now.AddYears(100);
                TempData[SD.Success] = "user Unlock successfully";
            }
            _db.SaveChanges();
            return RedirectToAction(nameof(Index));

        }
        [HttpPost]
        public IActionResult Delete (string userId) 
        {
            var objfrom = _db.applicationUsers.FirstOrDefault(u => u.Id == userId);
            if(objfrom == null)
            {
                return NotFound();

            }
            _db.applicationUsers.Remove(objfrom);
            _db.SaveChanges();
            TempData[SD.Success] = "User Delete Successfully";
            return RedirectToAction(nameof(Index)); 
        }

    }
}
