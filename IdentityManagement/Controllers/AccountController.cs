using IdentityManagement.Models;
using IdentityManagement.Models.ViewModel;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManagement.Controllers
{
    public class AccountController : Controller
    {
        private readonly    UserManager<IdentityUser> _userManager;  
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailSender _emailSender;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
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
        public async Task<IActionResult> Login(LoginVm model, string? returnurl=null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
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
            if (ModelState.IsValid)
            {
                var user =await _userManager.FindByEmailAsync(model.Email);

                if (user == null)
                {
                    return RedirectToAction("ForgotPasswordConformation");

                }
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackurl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code },protocol:HttpContext.Request.Scheme);

                await _emailSender.SendEmailAsync(model.Email, "Reset Password -Identity Manager", "Please reset your password by clicking here : <a href=\"" + callbackurl + "\">link</a>");
                return RedirectToAction("ForgotPasswordConformation");
            }
            return View(nameof(model));
        }
        [HttpGet]
        public IActionResult ForgotPasswordConformation()
        {
            return View();
        }

        [HttpGet]
        public IActionResult ResetPasswordConformation()
        {
            return View();
        }
        [HttpGet]
        public IActionResult ResetPassword(string code = null)
        {
            return code == null ? View("error") : View();
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordVm model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user == null)
                {
                    return RedirectToAction("ResetPasswordConformation");

                }
              var results = await  _userManager.ResetPasswordAsync(user, model.Code,model.Password);
                if (results.Succeeded)
                {
                    return RedirectToAction("ResetPasswordConformation");

                }
                AddError(results);
            }
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
        public async Task<IActionResult> Register (RegisterVm model, string? returnurl =null)
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
