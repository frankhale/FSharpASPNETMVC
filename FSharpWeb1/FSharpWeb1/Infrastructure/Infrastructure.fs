namespace FSharpWeb1.Infrastructure

open System
open System.Security.Claims
open System.Threading.Tasks
open Microsoft.Owin
open Microsoft.Owin.Security
open Microsoft.AspNet.Identity
open Microsoft.AspNet.Identity.EntityFramework
open Microsoft.AspNet.Identity.Owin
open System.Web.Mvc

// Thanks to http://stackoverflow.com/a/5341186/170217 for this!
module Collections = 
  let inline init s =
    let coll = new ^t()
    Seq.iter (fun (k,v) -> (^t : (member Add : 'a * 'b -> unit) coll, k, v)) s
    coll

module Helpers =
  // Thank you Tomas Petricek!!! http://stackoverflow.com/a/8150139/170217
  let (?<-) (viewData:ViewDataDictionary) (name:string) (value:'T) =
    viewData.Add(name, box value)

type EmailService() =
  interface IIdentityMessageService with
    member this.SendAsync (message:IdentityMessage) : Task =
      // Plug in your email service here to send an email.
      Task.FromResult(0) :> Task

type RouteValues = { ReturnUrl:string; RememberMe:bool }

type SmsService() =
  interface IIdentityMessageService with
    member this.SendAsync (message:IdentityMessage) : Task = 
      // Plug in your SMS service here to send a text message.
      Task.FromResult(0) :> Task

[<AllowNullLiteral>]
type ApplicationUser() =
  inherit IdentityUser()

  member this.GenerateUserIdentityAsync (manager:UserManager<ApplicationUser>) : Task<ClaimsIdentity> = 
    let userIdentity = 
      async {
        let! um = manager.CreateIdentityAsync (this, DefaultAuthenticationTypes.ApplicationCookie)
                  |> Async.AwaitTask 
        return um
      } |> Async.StartAsTask

    userIdentity
    
type ApplicationDbContext() =
  inherit IdentityDbContext<ApplicationUser>("DefaultConnection", false)
  
  static member Create() =
    new ApplicationDbContext()

[<AllowNullLiteral>]
type ApplicationUserManager(store:IUserStore<ApplicationUser>) =
  inherit UserManager<ApplicationUser>(store)
  
  static member Create(options:IdentityFactoryOptions<ApplicationUserManager>, context:IOwinContext) =  
    let manager = new ApplicationUserManager(new UserStore<ApplicationUser>(context.Get<ApplicationDbContext>()))
    
    // Configure validation logic for usernames
    let userValidator = UserValidator<ApplicationUser> (manager)
    userValidator.AllowOnlyAlphanumericUserNames <- false
    userValidator.RequireUniqueEmail <- true
    
    manager.UserValidator <- userValidator
       
    // Configure validation logic for passwords
    let passwordValidator = PasswordValidator()
    passwordValidator.RequiredLength <- 6
    passwordValidator.RequireNonLetterOrDigit <- true
    passwordValidator.RequireDigit <- true
    passwordValidator.RequireLowercase <- true
    passwordValidator.RequireUppercase <- true

    manager.PasswordValidator <- passwordValidator

    // Configure user lockout defaults
    manager.UserLockoutEnabledByDefault <- true
    manager.DefaultAccountLockoutTimeSpan <- TimeSpan.FromMinutes(5.0)
    manager.MaxFailedAccessAttemptsBeforeLockout <- 5

    // Register two factor authentication providers. This application uses Phone and Emails as a step of receiving a code for verifying the user
    // You can write your own provider and plug it in here.
    let phoneNumberTokenProvider = PhoneNumberTokenProvider<ApplicationUser>()
    phoneNumberTokenProvider.MessageFormat <- "Your security code is {0}"

    manager.RegisterTwoFactorProvider("Phone Code", phoneNumberTokenProvider)

    let emailTokenProvider = EmailTokenProvider<ApplicationUser>()
    emailTokenProvider.Subject <- "Security Code"
    emailTokenProvider.BodyFormat <- "Your security code is {0}"

    manager.RegisterTwoFactorProvider("Email Code", emailTokenProvider)
    manager.EmailService <- EmailService()
    manager.SmsService <- SmsService()

    let dataProtectionProvider = 
      if options.DataProtectionProvider <> null then
        manager.UserTokenProvider <- 
          new DataProtectorTokenProvider<ApplicationUser>(options.DataProtectionProvider.Create("ASP.NET Identity"))

    manager

[<AllowNullLiteral>]
type ApplicationSignInManager(userManager:ApplicationUserManager, authenticationManager:IAuthenticationManager) =
  inherit SignInManager<ApplicationUser, string>(userManager, authenticationManager)
  
  override this.CreateUserIdentityAsync(user:ApplicationUser) =
    let um = this.UserManager :?> ApplicationUserManager
    
    let result =
      async {
        let! genUID = user.GenerateUserIdentityAsync(um)
                      |> Async.AwaitTask
        return genUID
      } |> Async.StartAsTask
        
    result
    
  static member Create (options:IdentityFactoryOptions<ApplicationSignInManager>, context:IOwinContext) =
    new ApplicationSignInManager(context.GetUserManager<ApplicationUserManager>(), context.Authentication)