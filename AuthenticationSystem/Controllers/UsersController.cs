using AuthenticationSystem.Models.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace AuthenticationSystem.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly UserManager<IdentityUser> userManager;
        private readonly SignInManager<IdentityUser> signInManager;
        private string SecretKey = "Thisisasecretkeyanditshouldbeuitlizedproperly";

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

        //[Authorize]
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
                var token = CreateToken(userData);
                return Ok(new { Message = "Login Successfull.", Token =  token });
            }
            else
            {
                return BadRequest(new { Message = "Login Failed."});
            }
        }

        [Authorize]
        [HttpGet("Test1")]
        public IActionResult Test1()
        {
            return Ok(new { Message = "Mission 1 Successfull" });
        }

        [HttpGet("Test2")]
        public IActionResult Test2()
        {
            return Ok(new { Message = "Mission 2 Successfull" });
        }


        [HttpGet("CreateToken")]
        public string CreateToken(IdentityUser user)
        {
            var authorizationClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email ),
                new Claim(ClaimTypes.MobilePhone, user.PhoneNumber)
            };
            var signInKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(SecretKey));

            var token = new JwtSecurityToken(
                issuer: null,
                audience: null,
                expires: DateTime.Now.AddHours(2),
                claims: authorizationClaims,
                signingCredentials: new SigningCredentials(signInKey, SecurityAlgorithms.HmacSha256Signature));

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }
    }
}
