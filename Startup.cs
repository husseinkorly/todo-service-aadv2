using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Identity.Web;
using TodoApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;

namespace todoservice
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<TodoContext>(opt => opt.UseInMemoryDatabase("TodoList"));

            /**
                Using Microsoft-identity-web for decrypting and validating JWE token
            **/
            //services.AddMicrosoftIdentityWebApiAuthentication(Configuration);

            /**
                OR Decrypting and validating without the library
            **/
            // loading encryption cert from local machine
            X509Store store = new X509Store("MY", StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            var cert = store.Certificates.Find(X509FindType.FindByThumbprint, "<decription certificate>", false)[0];

            //// getting the signing keys
            var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever());
            var openIdConfig = configManager.GetConfigurationAsync().Result;

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
               .AddJwtBearer(options =>
               {
                   //options.Audience = "";
                   options.TokenValidationParameters = new TokenValidationParameters
                   {
                       TokenDecryptionKey = new X509SecurityKey(cert),
                       IssuerSigningKeys = openIdConfig.SigningKeys,
                       ValidAudiences = new List<string>
                       {
                           this.Configuration["AzureAd:ClientId"]
                       },
                       ValidateAudience = false,
                       ValidateIssuer = false
                   };

                   options.Events = new JwtBearerEvents
                   {
                       OnTokenValidated = async context =>
                       {
                           context.HttpContext.Items.Add("decryptedToken", context.SecurityToken as JwtSecurityToken);
                           context.Success();
                           await Task.CompletedTask;
                       }
                   };
               });

            services.AddControllers();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
