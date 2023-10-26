using System.ComponentModel.DataAnnotations;

namespace appAuth_API.Shared
{
    public class NovaSenha
    {
        [Required]
        public string NewPassword { get; set; } = string.Empty;
        [Compare("NewPassword", ErrorMessage="A senha nos dois campos deve ser igual.")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}
