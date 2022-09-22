using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Api;
using Api.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Jose;
using Newtonsoft.Json;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Mvc;

var MyAllowSpecificOrigins = "_myAllowSpecificOrigins";
var builder = WebApplication.CreateBuilder(args);
// services
builder.Services.AddCors(options =>
{
	options.AddPolicy(name: MyAllowSpecificOrigins,
					  policy =>
					  {
						  policy.WithOrigins("https://localhost:7122").AllowAnyHeader()
						  .AllowAnyMethod().AllowAnyOrigin();
					  });
});

builder.Services.AddAntiforgery(options => options.HeaderName = "X-XSRF-TOKEN");

builder.Services.AddAuthentication(x =>
{
	x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
	x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(o =>
{
	var Key = Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"]);
	o.SaveToken = true;
	o.TokenValidationParameters = new TokenValidationParameters
	{
		ValidateIssuer = false,
		ValidateAudience = false,
		ValidateLifetime = true,
		ValidateIssuerSigningKey = true,
		ValidIssuer = builder.Configuration["JWT:Issuer"],
		ValidAudience = builder.Configuration["JWT:Audience"],
		IssuerSigningKey = new SymmetricSecurityKey(Key),
		ClockSkew = TimeSpan.Zero
	};
	o.Events = new JwtBearerEvents
	{
		OnAuthenticationFailed = context =>
		{
			if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
			{
				context.Response.Headers.Add("IS-TOKEN-EXPIRED", "true");
			}
			return Task.CompletedTask;
		}
	};
});

builder.Services.AddAuthorization();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddSwaggerGen(options =>
{
	options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
	{
		Description = "Standard Authorization header using the Bearer scheme (\"bearer {token}\")",
		In = ParameterLocation.Header,
		Name = "Authorization",
		Type = SecuritySchemeType.ApiKey
	});

	options.OperationFilter<Swashbuckle.AspNetCore.Filters.SecurityRequirementsOperationFilter>();
});
var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();
app.UseCors(MyAllowSpecificOrigins);
app.UseAuthentication();
app.UseAuthorization();

// load previous categories if exists

var categoriesList = new List<string>();
var recipesList = new List<Recipe>();

var jsonPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
string jsonFile = Path.Combine(Environment.CurrentDirectory, "Data.json");


var jsonPathCategory = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
string jsonFileCategory = Path.Combine(Environment.CurrentDirectory, "CategoriesInfo.json");

using (StreamReader r = new StreamReader(jsonFile))
{
	var Data = r.ReadToEnd();
	var Json = JsonConvert.DeserializeObject<List<Recipe>>(Data);
	if (Json != null)
	{
		recipesList = Json;
	}
}

using (StreamReader C = new StreamReader(jsonFileCategory))
{
	var Data = C.ReadToEnd();
	var Json = JsonConvert.DeserializeObject<List<string>>(Data);
	if (Json != null)
	{
		categoriesList = Json;
	}
}
var usersList = new List<Client>();
// load previous Users if exists
var jsonPathUser = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
string jsonFileUser = Path.Combine(Environment.CurrentDirectory, "UsersInfo.json");

using (StreamReader r = new StreamReader(jsonFileUser))
{
	var Data = r.ReadToEnd();
	var Json = JsonConvert.DeserializeObject<List<Client>>(Data);
	if (Json != null)
	{
		usersList = Json;
	}
}

string GenerateRefreshToken()
{
	var randomNumber = new byte[32];
	using (var rng = RandomNumberGenerator.Create())
	{
		rng.GetBytes(randomNumber);
		return Convert.ToBase64String(randomNumber);
	}
}

Jwt? GenerateJWT(Client user)
{
	var tokenHandler = new JwtSecurityTokenHandler();
	var tokenKey = Encoding.UTF8.GetBytes(app.Configuration["JWT:Key"]);
	var tokenDescriptor = new SecurityTokenDescriptor
	{
		Subject = new ClaimsIdentity(new Claim[]
		{
				new Claim(ClaimTypes.Name, user.Name)
		}),
		Expires = DateTime.UtcNow.AddMinutes(10),
		SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
	};
	var token = tokenHandler.CreateToken(tokenDescriptor);
	return new Jwt { Token = tokenHandler.WriteToken(token), RefreshToken = GenerateRefreshToken() };
}

Jwt? Authenticate(Client user)
{
	PasswordHasher<string> pw = new();

	if (!usersList.Any(x => x.Name == user.Name && pw.VerifyHashedPassword(user.Name, x.Password, user.Password) == PasswordVerificationResult.Success))
	{
		return null;
	}

	// Else we generate JSON Web Token
	return GenerateJWT(user);
}

Jwt? Refresh(Jwt jwt)
{
	Client user;

	if (usersList.Find(x => x.RefreshToken == jwt.RefreshToken) is Client tempUser)
		user = tempUser;
	else
		return null;

	// Else we generate JSON Web Token
	var tokenHandler = new JwtSecurityTokenHandler();
	var tokenKey = Encoding.UTF8.GetBytes(app.Configuration["JWT:Key"]);
	var tokenDescriptor = new SecurityTokenDescriptor
	{
		Subject = new ClaimsIdentity(new Claim[]
		{
				new Claim(ClaimTypes.Name, user.Name)
		}),
		Expires = DateTime.UtcNow.AddMinutes(10),
		SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
	};
	var token = tokenHandler.CreateToken(tokenDescriptor);
	return new Jwt { Token = tokenHandler.WriteToken(token), RefreshToken = GenerateRefreshToken() };
}

// user enpoint
app.MapPost("/register", async (HttpContext context, IAntiforgery forgeryService, [FromBody] Client user) =>
{
	if (user.Name == String.Empty || user.Password == String.Empty || usersList.Exists(oldUser => oldUser.Name == user.Name))
	{
		return Results.BadRequest();
	}

	PasswordHasher<string> pw = new();
	user.Password = pw.HashPassword(user.Name, user.Password);
	usersList.Add(user);

    var token = GenerateJWT(user);

	if (token == null)
	{
		return Results.Unauthorized();
	}

	user.RefreshToken = token.RefreshToken;
	await SaveAsync();
	return Results.Created($"/users/{user.Name}", token);
});

app.MapPost("/login", async (HttpContext context, IAntiforgery forgeryService, Client user) =>
{
	var token = Authenticate(user);

	if (token == null)
	{
		return Results.Unauthorized();
	}

	PasswordHasher<string> pw = new();

	if (usersList.Find(x => x.Name == user.Name && pw.VerifyHashedPassword(user.Name, x.Password, user.Password) == PasswordVerificationResult.Success) is Client tempUser)
	{
		tempUser.RefreshToken = token.RefreshToken;
		await SaveAsync();
	}

	return Results.Ok(token);
});

app.MapGet("/antiforgery/token", [Authorize] (IAntiforgery forgeryService, HttpContext context) =>
{
	var tokens = forgeryService.GetAndStoreTokens(context);
	context.Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken!,
			new CookieOptions { HttpOnly = false });
});

app.MapPost("/refresh", async (Jwt jwt) =>
{
	var token = Refresh(jwt);

	if (token == null)
	{
		return Results.Unauthorized();
	}

	if (usersList.Find(x => x.RefreshToken == jwt.RefreshToken) is Client tempUser)
	{
		usersList.Remove(tempUser);
		tempUser.RefreshToken = token.RefreshToken;
		usersList.Add(tempUser);
		await SaveAsync();
	}

	return Results.Ok(token);
});

// recipe endpoints
app.MapGet("/recipes", [Authorize] async (HttpContext context, IAntiforgery forgeryService) =>
{
	try
	{
		await forgeryService.IsRequestValidAsync(context);
		return Results.Ok(recipesList);
    }
    catch(Exception ex)
    {
		return Results.BadRequest();
    }
});

app.MapGet("/recipes/{id}", [Authorize] async ([FromBody]Guid id, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.IsRequestValidAsync(context);
	if (recipesList.Find(recipe => recipe.Id == id) is Recipe recipe)
	{
		return Results.Ok(recipe);
	}
	return Results.NotFound();
});

app.MapPost("/recipes", [Authorize] async ([FromBody] Recipe recipe, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.IsRequestValidAsync(context);
	if (recipe.Title == String.Empty)
	{
		return Results.BadRequest();
	}
	recipe.Id = Guid.NewGuid();
	recipesList.Add(recipe);
	recipesList = recipesList.OrderBy(o => o.Title).ToList();
	await SaveAsync();
	return Results.Created($"/recipes/{recipe.Id}", recipe);
});

app.MapDelete("/recipes/{id}", [Authorize]   async([FromRoute(Name = "id")] Guid id, HttpContext context, IAntiforgery forgeryService) =>
{
	 await forgeryService.IsRequestValidAsync(context);
	if (recipesList.Find(recipe => recipe.Id == id) is Recipe recipe)
	{
		recipesList.Remove(recipe);
		 SaveAsync();
		return Results.Ok(recipe);
	}
	return Results.NotFound();
});

app.MapPut("/recipes/{id}", [Authorize] async ([FromBody] Recipe editedRecipe, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.IsRequestValidAsync(context);
	if (recipesList.Find(recipe => recipe.Id == editedRecipe.Id) is Recipe recipe)
	{
		recipesList.Remove(recipe);
		recipesList.Add(editedRecipe);
		recipesList = recipesList.OrderBy(o => o.Title).ToList();
		await SaveAsync();
		return Results.NoContent();
	}
	return Results.NotFound();
});

// category endpoints
app.MapGet("/category", [Authorize] async (HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.IsRequestValidAsync(context);
	return Results.Ok(categoriesList);
});

app.MapPost("/category", [Authorize] async (string category, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.IsRequestValidAsync(context);
	if (category == String.Empty || categoriesList.Contains(category))
	{
		return Results.BadRequest();
	}

	categoriesList.Add(category);
	categoriesList = categoriesList.OrderBy(o => o).ToList();

	await SaveAsync();
	return Results.Created($"/category/{category}", category);
});

app.MapDelete("/category/{category}", [Authorize] async (string category, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.IsRequestValidAsync(context);
	if (category == String.Empty)
	{
		return Results.BadRequest();
	}

	if (!categoriesList.Contains(category))
	{
		return Results.NotFound();
	}

	foreach (Recipe recipe in recipesList)
	{
		recipe.Categories.Remove(category);
	}
	categoriesList.Remove(category);
	await SaveAsync();
	return Results.Ok(category);
});

app.MapPut("/category/{oldCategory}", [Authorize] async ([FromRoute(Name = "oldCategory")] string oldCategory,  string editedCategory, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.IsRequestValidAsync(context);
	if (editedCategory == String.Empty)
	{
		return Results.BadRequest();
	}

	if (!categoriesList.Contains(oldCategory))
	{
		return Results.NotFound();
	}

	categoriesList.Remove(oldCategory);
	categoriesList.Add(editedCategory);
	categoriesList = categoriesList.OrderBy(o => o).ToList();

	foreach (var recipe in recipesList)
	{
		if (recipe.Categories.Contains(oldCategory))
		{
			recipe.Categories.Remove(oldCategory);
			recipe.Categories.Add(editedCategory);
		}
	}

	await SaveAsync();
	return Results.NoContent();
});

async Task SaveAsync()
{
	await Task.WhenAll(
		File.WriteAllTextAsync(jsonFile, System.Text.Json.JsonSerializer.Serialize(recipesList, new JsonSerializerOptions { WriteIndented = true })),
		File.WriteAllTextAsync(jsonFileCategory, System.Text.Json.JsonSerializer.Serialize(categoriesList, new JsonSerializerOptions { WriteIndented = true })),
		File.WriteAllTextAsync(jsonFileUser, System.Text.Json.JsonSerializer.Serialize(usersList, new JsonSerializerOptions { WriteIndented = true }))
		);
}

app.Run();