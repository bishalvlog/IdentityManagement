using IdentityManagement.Models;
using IdentityManagement.Models.ViewModel;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManagement.Controllers
{
    public class AccountController : Controller
    {
        private readonly    UserManager<IdentityUser> _userManager;  
        private readonly SignInManager<IdentityUser> _signInManager;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public  IActionResult Login(string returnurl =null)
        {
            ViewData["ReturnUrl"] = returnurl;
            return View();

        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginVm model, string returnurl=null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
            if (!ModelState.IsValid)
            {
                var result = await  _signInManager.PasswordSignInAsync(model.Email,model.Password,model.RememberMe,lockoutOnFailure:true);
               
                if (result.Succeeded)
                {
                   
                    return LocalRedirect(returnurl);
                }
                if (result.IsLockedOut)
                {
                    return View("Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid Login Attempt.");
                    return View(model);
                }
               
            }
            return View(nameof(model));
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
           
            return View();

        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordVm model)
        {
            return View(nameof(model));
        }

        [HttpGet]
        public async Task<IActionResult> Register(string returnurl=null)
        {
            ViewData["ReturnUrl"]=returnurl;
            RegisterVm registerVm = new RegisterVm();   
            return View(registerVm);    

        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register (RegisterVm model, string returnurl =null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl =returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email, Name = model.Name };
                var results = await _userManager.CreateAsync(user, model.Password); 
                if(results.Succeeded) 
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return LocalRedirect(returnurl);
                }
                AddError(results);
            }
            return View (nameof(model));
        }

        public async Task<IActionResult> LogOff()
        {
           await _signInManager.SignOutAsync(); 
            return RedirectToAction(nameof(HomeController.Index),"Home");
        }
        private void AddError(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);  
            }

        }

    }
}
