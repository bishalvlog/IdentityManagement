using IdentityManagement.Data;
using IdentityManagement.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityManagement.Controllers
{
    [BindProperties]
    public class RolesController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        public RolesController(ApplicationDbContext context, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _context = context;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public IActionResult Index()
        {
            var roles = _context.Roles.ToList();
            return View(roles);
        }
        [HttpGet]
        public async Task<IActionResult> Upsert(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return View();

            }
            else
            {
                //update
                var obj = _context.Roles.FirstOrDefault(u => u.Id == id);
                return View(obj);
            }

        }
        [HttpPost]
        [ValidateAntiForgeryToken]

        public async Task <IActionResult> Upsert(IdentityRole rolesdb)
        {
            if(await _roleManager.RoleExistsAsync(rolesdb.Name))
            {
                //error
                TempData[SD.Error] = "Role already Exits";
                return RedirectToAction(nameof(Index));

            }
            if(string.IsNullOrEmpty(rolesdb.Id))
            {
                //create
                await _roleManager.CreateAsync(new IdentityRole () { Name = rolesdb.Name });
                TempData[SD.Success] = "Role is Created Successfully";

            }
            else
            {
                //Update
                var objrole = _context.Roles.FirstOrDefault(u=>u.Id == rolesdb.Id);
                if(objrole == null)
                {
                    TempData[SD.Error] = "Role not found";
                    return RedirectToAction(nameof(Index));
                }
                objrole.Name = rolesdb.Name;
                objrole.NormalizedName = rolesdb.Name.ToUpper();
                var result = await _roleManager.UpdateAsync(objrole);
                TempData[SD.Success] = "Role is Updates Successfully";
            }
            return RedirectToAction(nameof(Index));
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete (string id)
        {
            var objfrom =_context.Roles.FirstOrDefault(u=> u.Id == id);
            var userRolesforThisRole = _context.UserRoles.Where(u => u.RoleId == id).Count();
            if(userRolesforThisRole > 0)
            {
                TempData[SD.Error] = "Cannot delete this role, since there are user assigned to this roles";
                return RedirectToAction(nameof(Index));
            }
            if (objfrom == null)
            {
                TempData[SD.Error] = "Role not found";
                return RedirectToAction(nameof(Index));

            }
            await _roleManager.DeleteAsync(objfrom);
            TempData[SD.Success] = "Role Delele Successfully.";
            return RedirectToAction(nameof(Index));
        }
    }
}
