namespace appAuth_API.Shared
{
    public class UserSession
    {
        public int UserNumber { get; set; }
        public string UserName { get; set; }
        public string UserEmail { get; set; }
        public string UserRole { get; set; }
        public string Token { get; set; }
    }
}
