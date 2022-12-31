using System.Text;
using System.Security.Cryptography;
using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using API.DTOs;
using Microsoft.EntityFrameworkCore;
using API.Interfaces;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _context = context;
        }

        // Register Function
        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
        {
            if (await UserExists(registerDto.Username)) return BadRequest("username is taken");

            using var hmc = new HMACSHA512();
            var user = new AppUser
            {
                UserName = registerDto.Username.ToLower(),
                PasswordHash = hmc.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmc.Key
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

        // Login Function

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            var user = await _context.Users.FirstOrDefaultAsync(x => x.UserName == loginDto.Username.ToLower());

            if (user == null) return Unauthorized("Invalid username");

            using var hmc = new HMACSHA512(user.PasswordSalt);

            var computedHash = hmc.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid password");
            }

            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

        // check if the username exists in the database or not
        private async Task<bool> UserExists(string username)
        {
            return await _context.Users.AnyAsync(x => x.UserName == username.ToLower());

        }
    }
}