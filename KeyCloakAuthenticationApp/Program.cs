using KeyCloakAuthenticationApp.Configuration;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

var keycloakSettings = builder.Configuration
    .GetSection("Keycloak-Settings")
    .Get<KeycloakSettings>();

builder.Services.AddControllersWithViews();
builder.Services.AddAuthorization();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(
    o =>
    {
        o.RequireHttpsMetadata = keycloakSettings.RequireHttpsMetadata;
        o.Audience = keycloakSettings.Audience;
        o.MetadataAddress = keycloakSettings.MetadataAddress;
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = keycloakSettings.ValidIssuer
        };
    });

builder.Services.AddSwaggerGen(opt =>
{
    opt.SwaggerDoc("v1", new OpenApiInfo { Title = "MyAPI", Version = "v1" });
    opt.AddSecurityDefinition("Keycloak", new OpenApiSecurityScheme
    {

        Type = SecuritySchemeType.OAuth2,
        Flows = new OpenApiOAuthFlows
        {
            Implicit = new OpenApiOAuthFlow
            {
                AuthorizationUrl = new Uri(keycloakSettings.AuthorizationUrl),
                Scopes = new Dictionary<string, string>
                {
                    {"openid","openid" },
                    {"profile","profile" }
                }
            }
        }

    });

    opt.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type=ReferenceType.SecurityScheme,
                    Id="Keycloak"
                },
                In = ParameterLocation.Header,
                Name = "Bearer",
                Scheme = "Bearer"

            },
            new string[]{}
        }
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "MyAPI v1"));
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.MapGet("users/me", (ClaimsPrincipal claims) =>
{
    return claims.Claims.ToDictionary(c => c.Type, c => c.Value);
}).RequireAuthorization();

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
