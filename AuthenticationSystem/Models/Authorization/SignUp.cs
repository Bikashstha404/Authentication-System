using System.ComponentModel.DataAnnotations;

namespace AuthenticationSystem.Models.Authorization
{
    public class SignUp
    {
        public Guid Id { get; set; }
        [Required]
        public string Name { get; set; }
        [Required]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
        [Required]
        public string ConfirmPassword { get; set; }
        [Required]
        public string PhoneNumber { get; set; }

    }
}
