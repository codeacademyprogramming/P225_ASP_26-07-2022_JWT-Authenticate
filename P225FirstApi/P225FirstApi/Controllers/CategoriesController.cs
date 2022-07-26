using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using P225FirstApi.Data;
using P225FirstApi.Data.Entities;
using P225FirstApi.DTOs.CategoryDTOs;
using P225FirstApi.Interfaces;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace P225FirstApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Roles ="SuperAdmin,Admin")]
    public class CategoriesController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IMapper _mapper;
        private readonly IJWTManager _jWTManager;
        private readonly UserManager<AppUser> _userManager;

        public CategoriesController(AppDbContext context, IMapper mapper, IJWTManager jWTManager, UserManager<AppUser> userManager)
        {
            _context = context;
            _mapper = mapper;
            _jWTManager = jWTManager;
            _userManager = userManager;
        }

        [HttpPost]
        public async Task<IActionResult> Post([FromForm] CategoryPostDto categoryPostDto)
        {
            //if (categoryPostDto.Esasdirmi)
            //{
            //    if (categoryPostDto.Sekil == null) return BadRequest("Sekil Is Required");
            //}
            //else
            //{
            //    if (categoryPostDto.AidOlduguKategoriyaninIdsi == null) return BadRequest("Aid Oldugu Kategoriyanin Id-si Is Required");

            //    if(!await _context.Categories.AnyAsync(c=>!c.IsDeleted && c.IsMain && c.Id == categoryPostDto.AidOlduguKategoriyaninIdsi)) return BadRequest("Aid Oldugu Kategoriyanin Id-si Is InCorrect");

            //    if(await _context.Categories.AnyAsync(c=>!c.IsDeleted && c.Name.ToLower() == categoryPostDto.Ad.Trim().ToLower())) 
            //        return BadRequest($"Category Ad = {categoryPostDto.Ad} Is Alredy Exists");
            //}

            //Category category = new Category();

            //category.Name = categoryPostDto.Ad.Trim();
            //category.CreatedAt = DateTime.UtcNow.AddHours(4);
            //category.IsMain = categoryPostDto.Esasdirmi;
            //category.ParentId = categoryPostDto.AidOlduguKategoriyaninIdsi;
            //category.Image = categoryPostDto.Sekil;

            string userName = _jWTManager.GetUserNameByToken(Request.Headers["Authorization"].ToString().Split(" ")[1]);

            AppUser appUser = await _userManager.FindByNameAsync(userName);

            if (appUser == null) return BadRequest("InCorrect Token");

            Category category = _mapper.Map<Category>(categoryPostDto);
            category.AppUserId = appUser.Id;

            await _context.Categories.AddAsync(category);
            await _context.SaveChangesAsync();

            //CategoryGetDto categoryGetDto = new CategoryGetDto
            //{
            //    Id = category.Id,
            //    Ad = category.Name,
            //    AidOlduguKategoriyaninIdsi = category.ParentId,
            //    Esasdirmi = category.IsMain,
            //    Sekil = category.Image
            //};

            CategoryGetDto categoryGetDto = _mapper.Map<CategoryGetDto>(category);

            return StatusCode(201, categoryGetDto);
        }

        [HttpGet]
        public async Task<IActionResult> Get()
        {
            //List<Category> categories = await _context.Categories.Where(c => !c.IsDeleted).ToListAsync();

            //List<CategoryListDto> categoryListDtos = new List<CategoryListDto>();

            //foreach (Category category in categories)
            //{
            //    CategoryListDto categoryListDto = new CategoryListDto
            //    {
            //        Id = category.Id,
            //        Ad = category.Name
            //    };

            //    categoryListDtos.Add(categoryListDto);
            //}

            //List<CategoryListDto> categoryListDtos = await _context.Categories
            //    .Where(c => !c.IsDeleted)
            //    .Select(x=>new CategoryListDto 
            //    {
            //        Id = x.Id,
            //        Ad = x.Name
            //    })
            //    .ToListAsync();

            List<CategoryListDto> categoryListDtos = _mapper.Map<List<CategoryListDto>>(await _context.Categories.Where(c => !c.IsDeleted).ToListAsync());

            return Ok(categoryListDtos);
        }

        [HttpGet]
        [Route("{id?}")]
        public async Task<IActionResult> Get(int? id)
        {
            if (id == null) return BadRequest("Id Is Required");

            Category category = await _context.Categories.FirstOrDefaultAsync(c => !c.IsDeleted && c.Id == id);

            if (category == null) return NotFound();

            //CategoryGetDto categoryGetDto = new CategoryGetDto
            //{
            //    Id = category.Id,
            //    Ad = category.Name,
            //    AidOlduguKategoriyaninIdsi = category.ParentId,
            //    Esasdirmi = category.IsMain,
            //    Sekil = category.Image
            //};

            CategoryGetDto categoryGetDto = _mapper.Map<CategoryGetDto>(category);

            return Ok(categoryGetDto);
        }

        [HttpPut]
        [Route("{id?}")]
        public async Task<IActionResult> Put(int? id, CategoryPutDto categoryPutDto)
        {
            if (id == null) return BadRequest("Id Is Requeired");

            if (id != categoryPutDto.Id) return BadRequest("Id Is Not Macthed");

            Category dbCategory = await _context.Categories.FirstOrDefaultAsync(c => !c.IsDeleted && c.Id == id);

            if (dbCategory == null) return NotFound("Id Is InCorrect");

            //if (categoryPutDto.Esasdirmi)
            //{
            //    if (categoryPutDto.Sekil == null) return BadRequest("Sekil Is Required");
            //}
            //else
            //{
            //    if (categoryPutDto.AidOlduguKategoriyaninIdsi == null || categoryPutDto.AidOlduguKategoriyaninIdsi <= 0) return BadRequest("AidOlduguKategoriyaninIdsi IsRequired");

            //    if (categoryPutDto.AidOlduguKategoriyaninIdsi == id) return BadRequest("Id and AidOlduguKategoriyaninIdsi Is Same");

            //    if (!await _context.Categories.AnyAsync(c => !c.IsDeleted && c.Id == categoryPutDto.AidOlduguKategoriyaninIdsi)) return BadRequest("AidOlduguKategoriyaninIdsi Is InCorrect");
            //}

            //if (await _context.Categories.AnyAsync(c => !c.IsDeleted && c.Id != id && c.Name.ToLower() == categoryPutDto.Ad.Trim().ToLower()))
            //    return Conflict("Category Ad Alreade Exists");

            dbCategory.Name = categoryPutDto.Ad.Trim();
            dbCategory.IsMain = categoryPutDto.Esasdirmi;
            dbCategory.ParentId = categoryPutDto.AidOlduguKategoriyaninIdsi;
            dbCategory.Image = categoryPutDto.Sekil;
            dbCategory.UpdatedAt = DateTime.UtcNow.AddHours(4);

            //dbCategory = _mapper.Map<Category>(categoryPutDto);

            //_context.Categories.Update(dbCategory);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        [HttpDelete]
        [Route("{id?}")]
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null) return BadRequest("Id Is Requeired");

            Category dbCategory = await _context.Categories.FirstOrDefaultAsync(c => !c.IsDeleted && c.Id == id);

            if (dbCategory == null) return NotFound("Id Is InCorrect");

            dbCategory.IsDeleted = true;
            dbCategory.CreatedAt = DateTime.UtcNow.AddHours(4);

            await _context.SaveChangesAsync();

            return NoContent();
        }
    }
}
