using AuthenticationSystem.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    // Tells there is a jwt token that guards the api
    options.AddSecurityDefinition("BearerToken", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header, //Tells where the token is located (in the header)
        Name = "Authorization", // Name of the header where token is located
        Type = SecuritySchemeType.ApiKey
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme {
                Reference = new OpenApiReference {
                    Type = ReferenceType.SecurityScheme,
                    Id = "BearerToken"
                }
            },
            new string[] { }
        }
    });
});

builder.Services.AddDbContext<UserDataDbContext>(options =>
options.UseSqlServer(builder.Configuration.GetConnectionString("UserDataConnectionString")));

builder.Services.AddDefaultIdentity<IdentityUser>()
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<UserDataDbContext>();

builder.Services.AddAuthentication(auth =>
{
    auth.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme; // Authenticate the user by default
    auth.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme; // Handle the cases while accesssing data without being authenticated
}).AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false; // doesn't require secure connection
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding
        .UTF8.GetBytes("Thisisasecretkeyanditshouldbeuitlizedproperly")), // Should match with security key given during creating jwt token
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero,
    };
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
using(var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

    var roles = new[] { "Admin","Manager","User" };
    foreach(var role in roles)
    {
        if(!await roleManager.RoleExistsAsync(role))
        {
            await roleManager.CreateAsync(new IdentityRole(role));
        }
    }
}

app.Run();
