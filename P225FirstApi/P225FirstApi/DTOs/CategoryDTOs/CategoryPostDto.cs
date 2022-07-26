using FluentValidation;
using Microsoft.AspNetCore.Http;
using P225FirstApi.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace P225FirstApi.DTOs.CategoryDTOs
{
    public class CategoryPostDto
    {
        public string Ad { get; set; }
        public bool Esasdirmi { get; set; }
        public string Sekil { get; set; }
        public IFormFile File { get; set; }
        public Nullable<int> AidOlduguKategoriyaninIdsi { get; set; }
    }

    public class CategoryPostDtoValidator : AbstractValidator<CategoryPostDto>
    {
        private readonly AppDbContext _context;

        public CategoryPostDtoValidator(AppDbContext context)
        {
            _context = context;

            RuleFor(r => r.Ad)
                .MaximumLength(255).WithMessage("Maksimum 255 Simvol Ola Biler")
                .MinimumLength(4).WithMessage("Minimum 4 Simvol Ola Biler")
                .NotEmpty().WithMessage("Mecburidi Qaqa");

            RuleFor(x => x).Custom((x, ctx) =>
            {
                if (x.Esasdirmi)
                {
                    if (string.IsNullOrWhiteSpace(x.Sekil))
                    {
                        ctx.AddFailure(nameof(x.Sekil),"Sekil Mecburidi");
                    }
                    else if (x.Sekil.Length > 1000)
                    {
                        ctx.AddFailure(nameof(x.Sekil),"Sekil Maksumum 1000 Simvol Ola Biler");
                    }
                }
                else
                {
                    if (x.AidOlduguKategoriyaninIdsi == null || x.AidOlduguKategoriyaninIdsi <= 0)
                    {
                        ctx.AddFailure(nameof(x.AidOlduguKategoriyaninIdsi),"AidOlduguKategoriyaninIdsi Mecburidi");
                    }
                    else if (!_context.Categories.Any(c=>c.Id == x.AidOlduguKategoriyaninIdsi))
                    {
                        ctx.AddFailure(nameof(x.AidOlduguKategoriyaninIdsi), "AidOlduguKategoriyaninIdsi IS In Correct");
                    }
                }

                if (x.Ad != null && _context.Categories.Any(c=>c.Name.ToLower() == x.Ad.Trim().ToLower()))
                {
                    ctx.AddFailure(nameof(x.Ad),"Ad Alreade Exists");
                }
            });
        }
    }
}
