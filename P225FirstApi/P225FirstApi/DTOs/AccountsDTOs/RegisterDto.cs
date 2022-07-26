using FluentValidation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace P225FirstApi.DTOs.AccountsDTOs
{
    public class RegisterDto
    {
        public string UserName { get; set; }
        public string Name { get; set; }
        public string SurName { get; set; }
        public string Password { get; set; }
        public string Email { get; set; }
    }

    public class RegisterDtoValidator : AbstractValidator<RegisterDto>
    {
        public RegisterDtoValidator()
        {
            RuleFor(r => r.UserName).NotEmpty().WithMessage("UserName Is Required");
            RuleFor(r => r.Name)
                .MaximumLength(255).WithMessage("Name Maksimum Length must be 255 symbol");

            RuleFor(r => r.SurName)
                .MaximumLength(255).WithMessage("SurName Maksimum Length must be 255 symbol");

            RuleFor(r => r.Password)
                .MinimumLength(8).WithMessage("Password Minimum Length must be 8 symbol");

            RuleFor(r => r.Email)
                .EmailAddress().WithMessage("Mutleq Email Olmalidi")
                .NotEmpty().WithMessage("Email Is Required");

        }
    }
}
