using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

string key = "128kjk32jjhdf3243jhj32kjsdsdf";

builder.Services.AddAuthorization();
builder.Services.AddAuthentication("Bearer").AddJwtBearer(opt =>
{
    var signingkey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
    var SigningCredentials = new SigningCredentials(signingkey, SecurityAlgorithms.HmacSha256Signature);

    opt.RequireHttpsMetadata = false;

    opt.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateAudience = false,
        ValidateIssuer = false,
        IssuerSigningKey = signingkey,
    };
});

var app = builder.Build();

app.MapGet("/", () => "Hello World!");

app.MapGet("/protected", (ClaimsPrincipal user) => user.Identity?.Name)
    .RequireAuthorization();

app.MapGet("/protectedWithScope", (ClaimsPrincipal user) => user.Identity?.Name)
    .RequireAuthorization(p => p.RequireClaim("scope", "myapi:borracho"));

app.MapGet("/auth/{user}/{pass}", (string user, string pass) =>
{
  if ( user == "pato" && pass == "donald")
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var byteKey = Encoding.UTF8.GetBytes(key);
        var tokenDes = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[]
        {
                  new Claim(ClaimTypes.Name, user),
                  new Claim("Scope", "myapi:borracho")
        }),
            Expires = DateTime.UtcNow.AddMonths(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(byteKey), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDes);

        return tokenHandler.WriteToken(token);
    }  
  else
    {
        return "usuario invalido!";
    }
});

app.Run();
