using FluentValidation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace P225FirstApi.DTOs.AccountsDTOs
{
    public class LoginDto
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class LoginDtoValidator : AbstractValidator<LoginDto>
    {
        public LoginDtoValidator()
        {
            RuleFor(r => r.Password)
                .MinimumLength(8).WithMessage("Password Minimum Length must be 8 symbol");

            RuleFor(r => r.Email)
                .EmailAddress().WithMessage("Mutleq Email Olmalidi")
                .NotEmpty().WithMessage("Email Is Required");
        }
    }
}
