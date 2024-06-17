using AuthenticationSystem.Models.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace AuthenticationSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly SignInManager<IdentityUser> signInManager;

        public UsersController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
        }

        [HttpPost("SignUp")]

        public async Task<IActionResult> SignUp([FromForm] SignUp signUp)
        {
            var existingUser = await userManager.FindByEmailAsync(signUp.Email);
            if (existingUser != null) 
            {
                return BadRequest(new { Message = "Email address is already registered" });
            }
            if(signUp.ConfirmPassword != signUp.Password)
            {
                return BadRequest(new { Message = "Both given password are not the same." });
            }
            IdentityUser user = new IdentityUser
            {
                UserName = signUp.Name,
                Email = signUp.Email,
                PasswordHash = signUp.Password,
                PhoneNumber = signUp.PhoneNumber,
            };
            var result = await userManager.CreateAsync(user, signUp.Password);
            if (result.Succeeded)
            {
                return Ok(new { Message = "User created successfully" });
            }
            else
            {
                var errors = result.Errors.Select(e => e.Description).ToList();
                return BadRequest(new { Message = "Failed to create user", Errors = errors });
            }
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromForm] Login login)
        {
            var userData = await userManager.FindByEmailAsync(login.Email);
            if (userData == null)
            {
                return BadRequest(new { Message = "Invalid Email" });
            }

            var user = await signInManager.PasswordSignInAsync(userData.UserName, login.Password, false, false);
            if (user.Succeeded)
            {
                return Ok(new { Message = "Login Successfull." });
            }
            else
            {
                return BadRequest(new { Message = "Login Failed."});
            }
        }
    }
}
