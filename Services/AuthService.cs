using Azure.Identity;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using System.Security.Cryptography;

namespace appAuth_API.Services
{
    public class AuthService
    {
        private readonly DataContext _context;
        private readonly IConfiguration _configuration;

        public AuthService(DataContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        public async Task<ServiceResponse<List<User>>> ListarUsuarios()
        {
            var usuarios = new ServiceResponse<List<User>>
            {
                Data = await _context.Users.ToListAsync()
            };

            return usuarios;   
        }
        
        public async Task<ServiceResponse<List<User>>> CadastrarUsuario(User novoUsuario, string password)
        {

            var response = new ServiceResponse<List<User>>();
            if (await UsuarioExiste(novoUsuario.Email))
            {
                response.Success = false;
                response.Message = "Usuario já existe";
            }

            CriarPasswordHash(password, out byte[] passwordHash, out byte[] passwordSalt);

            novoUsuario.PasswordHash = passwordHash;
            novoUsuario.PasswordSalt = passwordSalt;

            _context.Users.Add(novoUsuario);
            await _context.SaveChangesAsync();

            response.Data = await _context.Users.ToListAsync();

            return response;
        }

        public async Task<ServiceResponse<UserSession>> Login (Login userLogin)
        {
            var userSession = new ServiceResponse<UserSession>();
            var usuario = await _context.Users.FirstOrDefaultAsync(x => x.Email.ToLower().Equals(userLogin.Email.ToLower()));

            if (usuario == null)
            {
                userSession.Success = false;
                userSession.Message = "Usuário não encontrado";
            }
            else if(!VerificarPasswordHash(userLogin.Password, usuario.PasswordHash, usuario.PasswordSalt))
            {
                userSession.Success = false;
                userSession.Message = "Senha incorreta";
            }
            else
            {
                var session = new UserSession
                {
                    UserNumber = usuario.Id,
                    UserEmail = usuario.Email,
                    UserName = usuario.Name,
                    UserRole = usuario.Role,
                    Token = CriarToken(usuario)
                };

                userSession.Data = session;
            }

            return userSession;
        }

        private string CriarToken(User usuario)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, usuario.Id.ToString()),
                new Claim(ClaimTypes.Name, usuario.Email),
                new Claim(ClaimTypes.Role, usuario.Role)
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8
                .GetBytes(_configuration.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims:claims,
                expires:DateTime.Now.AddDays(1),
                signingCredentials:creds);

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
                
        }

        public async Task<ServiceResponse<string>> MudarSenha(int userId, NovaSenha novaSenha)
        {
            var usuario = await _context.Users.FindAsync(userId);
            var response = new ServiceResponse<string>();

            if(usuario == null)
            {
                response.Success = false;
                response.Message = "Usuário não encontrado";
                response.Data = "Usuário não encontrado";
                return response;
            }

            CriarPasswordHash(novaSenha.ConfirmPassword, out byte[] passwordHash, out byte[] passwordSalt);
            
            usuario.PasswordHash = passwordHash;
            usuario.PasswordSalt = passwordSalt;

            await _context.SaveChangesAsync();

            response.Data = "Senha alterada com sucesso";

            return response;
        }

        private void CriarPasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt) 
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerificarPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }

        public async Task<bool> UsuarioExiste(string email)
        {
            if (await _context.Users.AnyAsync(usuario => usuario.Email.ToLower().Equals(email.ToLower())))
            {
                return true;
            }
            return false;
        }

        public async Task<ServiceResponse<UserSession>> BuscarUsuario(int userId)
        {
            var response = new ServiceResponse<UserSession>();
            var usuario = await _context.Users.FindAsync(userId);

            if (usuario == null)
            {
                response.Success = false;
                response.Message = "Usuário não existe.";

                return response;
            }

            var userSession = new UserSession
            {
                UserNumber = usuario.Id,
                UserName = usuario.Name,
                UserEmail = usuario.Email,
                UserRole = usuario.Role
            };

            response.Data = userSession;

            return response;
        }
    }
}
