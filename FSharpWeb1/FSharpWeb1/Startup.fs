
namespace FSharpWeb1

open System
open Owin
open Microsoft.Owin
open Microsoft.Owin.Security
open Microsoft.AspNet.Identity
open Microsoft.AspNet.Identity.Owin
open Microsoft.Owin.Security.Cookies
open Microsoft.Owin.Security.Google

open FSharpWeb1.Infrastructure

type Startup() =
  member this.Configuration (app : IAppBuilder) =
    this.ConfigureAuth(app)
  
  member this.ConfigureAuth(app : IAppBuilder) =
    // Configure the db context, user manager and signin manager to use a single instance per request
    app.CreatePerOwinContext(ApplicationDbContext.Create) |> ignore
    
    let applicationUserManagerCallback = Func<IdentityFactoryOptions<ApplicationUserManager>, IOwinContext, ApplicationUserManager>(fun x y -> ApplicationUserManager.Create(x, y))
    app.CreatePerOwinContext<ApplicationUserManager>(applicationUserManagerCallback) |> ignore
        
    let appSignInManagerCallback = Func<IdentityFactoryOptions<ApplicationSignInManager>, IOwinContext, ApplicationSignInManager>(fun x y -> ApplicationSignInManager.Create(x, y))
    app.CreatePerOwinContext<ApplicationSignInManager>(appSignInManagerCallback) |> ignore

    let cookieAuthOptions = CookieAuthenticationOptions()
    cookieAuthOptions.AuthenticationType <- DefaultAuthenticationTypes.ApplicationCookie
    cookieAuthOptions.LoginPath <- PathString("/Account/Login")
    
    let cookieAuthOptionsProvider = CookieAuthenticationProvider()
    // Enables the application to validate the security stamp when the user logs in.
    // This is a security feature which is used when you change a password or add an external login to your account.  
    cookieAuthOptionsProvider.OnValidateIdentity <- SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(validateInterval=TimeSpan.FromMinutes(30.0), regenerateIdentity = fun manager user -> user.GenerateUserIdentityAsync(manager))

    cookieAuthOptions.Provider <- cookieAuthOptionsProvider

    app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie)

    // Enables the application to temporarily store user information when they are verifying the second factor in the two-factor authentication process.
    app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5.0))

    // Enables the application to remember the second login verification factor such as phone or email.
    // Once you check this option, your second step of verification during the login process will be remembered on the device where you logged in from.
    // This is similar to the RememberMe option when you log in.
    app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

    // Uncomment the following lines to enable logging in with third party login providers
    //app.UseMicrosoftAccountAuthentication(
    //    clientId = "",
    //    clientSecret = "")

    //app.UseTwitterAuthentication(
    //   consumerKey = "",
    //   consumerSecret = "")

    //app.UseFacebookAuthentication(
    //   appId = "",
    //   appSecret = "")

    //let googleOAuth2AuthenticationOptions = GoogleOAuth2AuthenticationOptions()
    //googleOAuth2AuthenticationOptions.ClientId <- ""
    //googleOAuth2AuthenticationOptions.ClientSecret <- ""

[<assembly: OwinStartupAttribute(typeof<Startup>)>]
do()