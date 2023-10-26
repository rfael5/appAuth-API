using appAuth_API.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace appAuth_API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public readonly AuthService _authService;

        public AuthController(AuthService authService)
        {
            _authService = authService;
        }
        [HttpGet("listar")]
        public async Task<ActionResult<ServiceResponse<List<User>>>> ListarUsuarios()
        {
            var response = await _authService.ListarUsuarios();

            return Ok(response);

        }

        [HttpPost("cadastrar")]
        public async Task<ActionResult<ServiceResponse<List<User>>>> CadastrarUsuario(UserRegister novoUsuario)
        {
            var response = await _authService.CadastrarUsuario(novoUsuario.NewUser, novoUsuario.Password);

            return Ok(response);
        }

        [HttpPost("login")]
        public async Task<ActionResult<ServiceResponse<User>>> Login(Login userLogin)
        {
            var response = await _authService.Login(userLogin);

            return Ok(response);
        }

        [HttpPost("mudar-senha"), Authorize]
        public async Task<ActionResult<ServiceResponse<string>>> MudarSenha([FromBody] NovaSenha novaSenha)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var response = await _authService.MudarSenha(int.Parse(userId), novaSenha);

            if (response == null)
            {
                return null;
            }

            return Ok(response);
        }

        [HttpGet("buscar-usuario/{userId}")]
        public async Task<ActionResult<ServiceResponse<UserSession>>> BuscarUsuario(int userId)
        {
            var response = await _authService.BuscarUsuario(userId);

            return Ok(response);
        }


    }
}
