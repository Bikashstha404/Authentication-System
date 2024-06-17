﻿using AuthenticationSystem.Models.Domain;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationSystem.Data
{
    public class UserDataDbContext: IdentityDbContext
    {
        public UserDataDbContext(DbContextOptions<UserDataDbContext> options): base(options)
        {
            
        }

        public DbSet<User> Users { get; set; }
    }
}
