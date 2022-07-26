using P225FirstApi.Data.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace P225FirstApi.Interfaces
{
    public interface IJWTManager
    {
        Task<string> GenerateTokenAsync(AppUser appUser);

        string GetUserNameByToken(string token);
    }
}
