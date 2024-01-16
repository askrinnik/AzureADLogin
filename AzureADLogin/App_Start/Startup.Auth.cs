using System;
using System.Configuration;
using System.IdentityModel.Claims;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Owin;
using AzureADLogin.Models;

namespace AzureADLogin
{
    public partial class Startup
    {
        private static readonly string ClientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static readonly string AppKey = ConfigurationManager.AppSettings["ida:ClientSecret"];
        private static readonly string AadInstance = EnsureTrailingSlash(ConfigurationManager.AppSettings["ida:AADInstance"]);
        private static readonly string TenantId = ConfigurationManager.AppSettings["ida:TenantId"];
        private static readonly string PostLogoutRedirectUri = ConfigurationManager.AppSettings["ida:PostLogoutRedirectUri"];

        public static readonly string Authority = AadInstance + TenantId;

        // This is the resource ID of the AAD Graph API.  We'll need this to request a token to call the Graph API.
        private const string _graphResourceId = "https://graph.windows.net";

        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = ClientId,
                    Authority = Authority,
                    PostLogoutRedirectUri = PostLogoutRedirectUri,

                    Notifications = new OpenIdConnectAuthenticationNotifications()
                    {
                        // If there is a code in the OpenID Connect response, redeem it for an access token and refresh token, and store those away.
                       AuthorizationCodeReceived = (context) => 
                       {
                           var code = context.Code;
                           var credential = new ClientCredential(ClientId, AppKey);
                           var signedInUserId = context.AuthenticationTicket.Identity.FindFirst(ClaimTypes.NameIdentifier).Value;
                           var authContext = new AuthenticationContext(Authority, new AdalTokenCache(signedInUserId));
                           _ = authContext.AcquireTokenByAuthorizationCodeAsync(
                             code, new Uri(HttpContext.Current.Request.Url.GetLeftPart(UriPartial.Path)), credential, _graphResourceId).Result;

                           return Task.FromResult(0);
                       }
                    }
                });
        }

        private static string EnsureTrailingSlash(string value)
        {
            if (value == null)
            {
                value = string.Empty;
            }

            if (!value.EndsWith("/", StringComparison.Ordinal))
            {
                return value + "/";
            }

            return value;
        }
    }
}
