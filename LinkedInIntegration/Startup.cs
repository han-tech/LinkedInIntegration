using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using LinkedInIntegration.Data;
using LinkedInIntegration.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using System.Net.Http;
using Microsoft.AspNetCore.Authentication;
using System.Net.Http.Headers;
using Newtonsoft.Json.Linq;
using System.Security.Claims;

namespace LinkedInIntegration
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
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();
            services.ConfigureApplicationCookie(options => {
                options.LoginPath = "/Account/LogIn";
                options.LogoutPath = "/Account/LogOut";
            });
            services.AddAuthentication().AddOAuth(
                "LinkedIn", o =>
                {
                    // We need to specify an Authentication Scheme
                    // Configure the LinkedIn Client ID and Client Secret
                    o.ClientId = Configuration["linkedin:clientId"];
                    o.ClientSecret = Configuration["linkedin:clientSecret"];
                    // Set the callback path, so LinkedIn will call back to http://APP_URL/signin-linkedin 
                    // Also ensure that you have added the URL as an Authorized Redirect URL in your LinkedIn application
                    o.CallbackPath = new PathString("/signin-linkedin");
                    // Configure the LinkedIn endpoints                
                    o.AuthorizationEndpoint = "https://www.linkedin.com/oauth/v2/authorization";
                    o.TokenEndpoint = "https://www.linkedin.com/oauth/v2/accessToken";
                    o.UserInformationEndpoint = "https://api.linkedin.com/v1/people/~:(id,formatted-name,email-address,picture-url)";
                    o.Scope.Add("r_basicprofile");
                    o.Scope.Add("r_emailaddress");
                    o.Events = new OAuthEvents
                    {
                        // The OnCreatingTicket event is called after the user has been authenticated and the OAuth middleware has 
                        // created an auth ticket. We need to manually call the UserInformationEndpoint to retrieve the user's information,
                        // parse the resulting JSON to extract the relevant information, and add the correct claims.
                        OnCreatingTicket = async context =>
                        {
                            // Retrieve user info
                            var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
                            request.Headers.Add("x-li-format", "json"); // Tell LinkedIn we want the result in JSON, otherwise it will return XML
                            var response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted);
                            response.EnsureSuccessStatusCode();
                            // Extract the user info object
                            var user = JObject.Parse(await response.Content.ReadAsStringAsync());
                            // Add the Name Identifier claim
                            var userId = user.Value<string>("id");
                            if (!string.IsNullOrEmpty(userId))
                            {
                                context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userId, ClaimValueTypes.String, context.Options.ClaimsIssuer));
                            }
                            // Add the Name claim
                            var formattedName = user.Value<string>("formattedName");
                            if (!string.IsNullOrEmpty(formattedName))
                            {
                                context.Identity.AddClaim(new Claim(ClaimTypes.Name, formattedName, ClaimValueTypes.String, context.Options.ClaimsIssuer));
                            }
                            // Add the email address claim
                            var email = user.Value<string>("emailAddress");
                            if (!string.IsNullOrEmpty(email))
                            {
                                context.Identity.AddClaim(new Claim(ClaimTypes.Email, email, ClaimValueTypes.String,
                                    context.Options.ClaimsIssuer));
                            }
                            // Add the Profile Picture claim
                            var pictureUrl = user.Value<string>("pictureUrl");
                            if (!string.IsNullOrEmpty(email))
                            {
                                context.Identity.AddClaim(new Claim("profile-picture", pictureUrl, ClaimValueTypes.String,
                                    context.Options.ClaimsIssuer));
                            }
                        }
                    };
                });

            services.AddMvc()
                .AddRazorPagesOptions(options =>
                {
                    options.Conventions.AuthorizeFolder("/Account/Manage");
                    options.Conventions.AuthorizePage("/Account/Logout");
                });

            // Register no-op EmailSender used by account confirmation and password reset during development
            // For more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=532713
            services.AddSingleton<IEmailSender, EmailSender>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
            }

            app.UseStaticFiles();

            // Add the OAuth2 middleware
            app.UseAuthentication();
            
            app.Map("/login", builder =>
            {
                builder.Run(async context =>
                {
                    // Return a challenge to invoke the LinkedIn authentication scheme
                    await context.ChallengeAsync("LinkedIn", properties: new AuthenticationProperties() { RedirectUri = "/" });
                });
            });
            // Listen for requests on the /logout path, and sign the user out
            app.Map("/logout", builder =>
            {
                builder.Run(async context =>
                {
                    // Sign the user out of the authentication middleware (i.e. it will clear the Auth cookie)
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    // Redirect the user to the home page after signing out
                    context.Response.Redirect("/");
                });
            });
            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller}/{action=Index}/{id?}");
            });
        }
    }
}
