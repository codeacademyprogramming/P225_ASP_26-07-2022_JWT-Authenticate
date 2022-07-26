using AutoMapper;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using P225FirstApi.Data.Entities;
using P225FirstApi.DTOs.AccountsDTOs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Configuration;
using P225FirstApi.Interfaces;

namespace P225FirstApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountsController : ControllerBase
    {
        private readonly IMapper _mapper;
        private readonly UserManager<AppUser> _userManager;
        private readonly IJWTManager _jWTManager;

        public AccountsController(IMapper mapper, UserManager<AppUser> userManager, IJWTManager jWTManager)
        {
            _mapper = mapper;
            _userManager = userManager;
            _jWTManager = jWTManager;
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register(RegisterDto registerDto)
        {
            AppUser appUser = _mapper.Map<AppUser>(registerDto);

            IdentityResult identityResult = await _userManager.CreateAsync(appUser, registerDto.Password);

            if (!identityResult.Succeeded)
            {
                return BadRequest(identityResult.Errors);
            }

            identityResult = await _userManager.AddToRoleAsync(appUser, "SuperAdmin");

            return Ok();
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login(LoginDto loginDto)
        {
            AppUser appUser = await _userManager.FindByEmailAsync(loginDto.Email);

            if (appUser == null) return BadRequest("Email Or Password Is InCorrect");

            if (!await _userManager.CheckPasswordAsync(appUser,loginDto.Password)) return BadRequest("Email Or Password Is InCorrect");

            return Ok(new { token=await _jWTManager.GenerateTokenAsync(appUser) });
        }

        #region Create Role
        //[HttpGet]
        //[Route("createrole")]
        //public async Task<IActionResult> CreateRole()
        //{
        //    await _roleManager.CreateAsync(new IdentityRole { Name = "SuperAdmin" });
        //    await _roleManager.CreateAsync(new IdentityRole { Name = "Admin" });
        //    await _roleManager.CreateAsync(new IdentityRole { Name = "Member" });


        //    return Ok();
        //}
        #endregion
    }
}
