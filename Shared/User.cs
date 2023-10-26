namespace appAuth_API.Shared
{
    public class User
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
        public DateTime DataCreation { get; set; } = DateTime.Now;
        public string Role { get; set; } = string.Empty;
    }
}
