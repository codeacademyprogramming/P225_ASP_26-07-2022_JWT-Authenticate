using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using P225FirstApi.Data.Configurations;
using P225FirstApi.Data.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace P225FirstApi.Data
{
    public class AppDbContext : IdentityDbContext<AppUser>
    {
        //Migrations Commands
        //Add-Migration InitialCreate -OutputDir Data\Migrations
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options){}

        public DbSet<Category> Categories { get; set; }
        public DbSet<Brand> Brands { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            //modelBuilder.ApplyConfiguration(new CategoryConfiguration());
            //modelBuilder.ApplyConfiguration(new BrandConfiguration());

            modelBuilder.ApplyConfigurationsFromAssembly(typeof(AppDbContext).Assembly);

            base.OnModelCreating(modelBuilder);
        }
    }
}