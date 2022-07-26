using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using P225FirstApi.Data.Entities;
using P225FirstApi.Interfaces;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace P225FirstApi.Services
{
    public class JWTManager : IJWTManager
    {
        private readonly UserManager<AppUser> _userManager;
        private IConfiguration Configuration { get; }

        public JWTManager(UserManager<AppUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            Configuration = configuration;
        }

        public async Task<string> GenerateTokenAsync(AppUser appUser)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, appUser.Id),
                new Claim(ClaimTypes.Name,appUser.UserName),
                new Claim(ClaimTypes.Email,appUser.Email)
            };

            IList<string> roles = await _userManager.GetRolesAsync(appUser);

            foreach (string role in roles)
            {
                Claim claim = new Claim(ClaimTypes.Role, role);

                claims.Add(claim);
            }

            SymmetricSecurityKey symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration.GetSection("JWT:SecurityKey").Value));
            SigningCredentials signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha512);

            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(
                issuer: Configuration.GetSection("JWT:Issuer").Value,
                audience: Configuration.GetSection("JWT:Audience").Value,
                claims: claims,
                signingCredentials: signingCredentials,
                expires: DateTime.Now.AddHours(4)
                );

            JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

            return jwtSecurityTokenHandler.WriteToken(jwtSecurityToken);
        }

        public string GetUserNameByToken(string token)
        {
            return new JwtSecurityTokenHandler().ReadJwtToken(token).Claims.ToList().FirstOrDefault(c => c.Type == ClaimTypes.Name).Value;
        }
    }
}
