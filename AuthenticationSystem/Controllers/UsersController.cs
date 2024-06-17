using AuthenticationSystem.Models.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

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

        [HttpPost]
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
                return BadRequest(new { Message = "Failed to create user", Errors = result.Errors });
            }
        }
    }
}
