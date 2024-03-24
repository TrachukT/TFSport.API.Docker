using Microsoft.AspNetCore.Diagnostics;
using Microsoft.Azure.Cosmos;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Azure;
using Microsoft.OpenApi.Models;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json.Serialization;
using TFSport.API.AutoMapper;
using TFSport.API.Filters;
using TFSport.Services.Interfaces;
using TFSport.Services.Services;
using TFSport.Models.Entities;
using TFSport.Repository.Interfaces;
using TFSport.Repository.Repositories;
using TFSport.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Services.AddHttpClient();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddAutoMapper(typeof(MappingProfile));
builder.Services.AddScoped<IJWTService, JWTService>();
builder.Services.AddScoped<IUsersRepository, UsersRepository>();
builder.Services.AddScoped<CustomExceptionFilter>();
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

var allowedOrigins = builder.Configuration.GetSection("CORS:AllowedOrigins").Get<string[]>();

//builder.Services.AddCors(options =>
//{
//    options.AddPolicy("AllowSpecificOrigins",
//        builder =>
//        {
//            builder.WithOrigins(allowedOrigins)
//                   .AllowAnyHeader()
//                   .AllowAnyMethod()
//                   .AllowCredentials();
//        });
//});


builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8
                .GetBytes(builder.Configuration.GetSection("JWT:Secret").Value)),
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidAudience = builder.Configuration["JWT:ValidAudience"],
            ValidIssuer = builder.Configuration["JWT:ValidIssuer"],
            RequireExpirationTime = true,
            ValidateLifetime = true
        };
        options.SaveToken = true;
    });

builder.Services.AddControllers().AddJsonOptions(options =>
{
    options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
});



builder.Services.AddSwaggerGen(options =>
{
    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    options.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, xmlFile));

    options.SwaggerDoc("v1", new OpenApiInfo { Title = "TFSport.API", Version = "v1" });

    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Standard Authorization header using the Bearer scheme. Example: (\"Bearer {token}\")"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                },
            },
            new List<string>()
        }
    });

    options.EnableAnnotations();
});

CosmosClientOptions cosmos_options = new()
{
    HttpClientFactory = () => new HttpClient(new HttpClientHandler()
    {
        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
    }),
    ConnectionMode = ConnectionMode.Gateway,
};

using CosmosClient client = new(
  builder.Configuration.GetConnectionString("CosmosDb"),
  clientOptions: cosmos_options
);

builder.Services.AddSingleton(sp =>
{
    string connectionString = builder.Configuration.GetConnectionString("CosmosDb");
    return new CosmosClient(connectionString, clientOptions:cosmos_options);
});


builder.Services.AddCosmosRepository(options =>
{
    var cosmosConfiguration = builder.Configuration.GetSection("CosmosConfiguration");
    string databaseId;

    databaseId = cosmosConfiguration.GetValue<string>("DevDatabaseId");

    options.CosmosConnectionString = builder.Configuration.GetConnectionString("CosmosDb");
    options.DatabaseId = databaseId;
    options.ContainerPerItemType = true;

    options.ContainerBuilder
        .Configure<TFSport.Models.Entities.User>(containerOptionsBuilder =>
        {
            containerOptionsBuilder
                .WithContainer("Users")
                .WithPartitionKey("/partitionKey");
        });
}, x => {
    x.HttpClientFactory = () => new HttpClient(new HttpClientHandler()
    {
        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
    });
x.ConnectionMode = ConnectionMode.Gateway;
}
);


builder.Services.AddMemoryCache(options =>
{
    options.CompactionPercentage = 0.02;
    options.ExpirationScanFrequency = TimeSpan.FromMinutes(3);
    options.SizeLimit = 1000;
});

var app = builder.Build();

app.UseSwagger();

app.UseSwaggerUI();

app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
        context.Response.ContentType = "text/plain";

        var exceptionHandlerPathFeature =
            context.Features.Get<IExceptionHandlerPathFeature>();

        if (exceptionHandlerPathFeature?.Error is Exception error)
        {
            await context.Response.WriteAsync(error.Message).ConfigureAwait(false);
        }
    });
});

//app.UseHttpsRedirection();

app.UseAuthentication();

app.UseCors("AllowSpecificOrigins");

app.UseAuthorization();

app.MapControllers();

using (var scope = app.Services.CreateScope())
{
    var userService = scope.ServiceProvider.GetRequiredService<IUserService>();
    //userService.CreateSuperAdminUser().Wait();
}

app.Run();