using IdentityManagement.Models;
using IdentityManagement.Models.ViewModel;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace IdentityManagement.Controllers
{
    public class AccountController : Controller
    {
        private readonly    UserManager<IdentityUser> _userManager;  
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailSender _emailSender;
        private readonly UrlEncoder _Urlencoder;

        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IEmailSender emailSender,UrlEncoder Urlencoder, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _Urlencoder = Urlencoder;
            _roleManager = roleManager;
        }
        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public  IActionResult Login(string? returnurl =null)
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
                if (result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(VerifyAuthenticationCode),new {model.RememberMe,  returnurl });    
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
        public async Task<IActionResult> Register(string returnurl = null)
        {
            if(!await _roleManager.RoleExistsAsync("Admin"))
            {
                //Creat Role
                await _roleManager.CreateAsync(new IdentityRole("Admin"));
                await _roleManager.CreateAsync(new IdentityRole("User"));


            }
            ViewData["ReturnUrl"] = returnurl;
            RegisterVm registerVm = new RegisterVm();
            return View(registerVm);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
 
        public async Task<IActionResult> Register(RegisterVm model, string? returnurl = null)
        {
            ViewData["ReturnUrl"] = returnurl;
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { UserName = model.Email, Email = model.Email, Name = model.Name };
                var results = await _userManager.CreateAsync(user, model.Password);
                if (results.Succeeded)
                {
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    return LocalRedirect(returnurl);
                }
                AddError(results);
            }
            return View(nameof(model));
        }


        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
           
            return View();

        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
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
        [AllowAnonymous]
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
        
        public async Task<IActionResult> LogOff()
        {
           await _signInManager.SignOutAsync(); 
            return RedirectToAction(nameof(HomeController.Index),"Home");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public IActionResult ExternalLogin(string provider, string? returnurl =null )
        {
            var redirecturl =Url.Action("ExternalLoginCallback","Account", new { ReturnUrl = returnurl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirecturl);
            return  Challenge(properties,provider);

        }
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string? returnurl = null, string? remoteError =null)
        {
            returnurl = returnurl ?? Url.Content("~/");
            if (remoteError != null)
            {
                ModelState.AddModelError(string.Empty, $"Error from external provider:{remoteError}");
                return View(nameof(Login));
            }
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction(nameof( Login));

            }
            //signin user 
            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey,isPersistent:false);
            if(result.Succeeded)
            {
                // update authentication token
                await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
                return LocalRedirect(returnurl);
            }
            if (result.RequiresTwoFactor)
            {
                return RedirectToAction("VerifyAuthenticationCode", new {returnurl = returnurl});   
            }
            else
            {
                //if user doesnot have a account
                ViewData["ReturnUrl"] = returnurl;
                ViewData["ProviderDisplayName"] = info.ProviderDisplayName;
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                return View("ExternalLoginConfirmation", new ExternalLoginConfirmationVm { Email = email });
            }
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginConfirmation (ExternalLoginConfirmationVm confirmation, string? returnurl =null)
        {
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                var info =  await _signInManager.GetExternalLoginInfoAsync();

                if(info == null)
                { 
                    return View("Error");
                }
                var user =  new ApplicationUser { UserName =confirmation.Email, Email =confirmation.Email, Name=confirmation.Name};
                var result = await _userManager.CreateAsync(user);
                if(result.Succeeded) 
                {
                    result = await _userManager.AddLoginAsync(user, info);
                    if(result.Succeeded) 
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
                        return LocalRedirect(returnurl);
                    }
                }
                AddError(result);
            }
            ViewData["ReturnUrl"] = returnurl;
            return View(confirmation);

        }
        [HttpGet]
        public async Task<IActionResult> RemoveAuthenticator()
        {
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
          await _userManager.SetTwoFactorEnabledAsync(user, false);
            return RedirectToAction(nameof(Index),"Home");
        }
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> EnableAuthenticator()
        {
            string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
            
                var user = await _userManager.GetUserAsync(User);
                await _userManager.ResetAuthenticatorKeyAsync(user);
                var token = await _userManager.GetAuthenticatorKeyAsync(user);
            string AuthenticatorUrl = string.Format(AuthenticatorUriFormat,_Urlencoder.Encode("IdenetityManager"),_Urlencoder.Encode(user.Email),token);
                var model = new TwoFactorAuthenicationVm() { Token = token ,QRCodeUrl=AuthenticatorUrl};
                return View(model);
        }
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> EnableAuthenticator(TwoFactorAuthenicationVm model)
        {
            if(ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                var succeeded = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
            if(succeeded)
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
                }
                else
                {
                    ModelState.AddModelError("verify", "Your two factor auth could not be availabe");
                    return View(model);
                }
            }
            return RedirectToAction(nameof(AuthenticatorConfirmation));
        }
        public IActionResult AuthenticatorConfirmation()
        {
            return View();
        }
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> VerifyAuthenticationCode(bool rememberMe, string returnUlr = null)
        {
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                return View("Error");
            }
            return View(new VerifyAuthenticatorVm() {ReturnUrl=returnUlr, RememberMe = rememberMe, });

        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public async Task<IActionResult> VerifyAuthenticationCode(VerifyAuthenticatorVm model)
        {
            model.ReturnUrl = model.ReturnUrl ?? Url.Content("~/");
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.Code, model.RememberMe, rememberClient: true);
            if (result.Succeeded)
            {
                return LocalRedirect(model.ReturnUrl);
            }
            if (result.IsLockedOut)
            {
                return View("Lockout");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid code");
                return View(model);
            }

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
