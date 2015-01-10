namespace FSharpWeb1.Controllers

open System
open System.Globalization
open System.Linq
open System.Security.Claims
open System.Threading.Tasks
open System.Web
open System.Web.Mvc
open Microsoft.AspNet.Identity
open Microsoft.AspNet.Identity.Owin
open Microsoft.Owin.Security

open FSharpWeb1.Infrastructure
open FSharpWeb1.Infrastructure.Helpers
open FSharpWeb1.Models

[<Authorize>]
type AccountController(userManager:ApplicationUserManager, signInManager:ApplicationSignInManager) =
  inherit Controller()

  let mutable _signInManager : ApplicationSignInManager = signInManager
  let mutable _userManager : ApplicationUserManager = userManager

  member this.SignInManager
    with get () = 
      match _signInManager with
      | null -> this.HttpContext.GetOwinContext().Get<ApplicationSignInManager>()
      | _ -> _signInManager
    and set (value) = _signInManager <- value

  member this.UserManager
    with get () = 
      match _userManager with
      | null -> this.HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>()
      | _ -> _userManager
    and set (value) = _userManager <- value

  new() = new AccountController()

  member private this.RedirectToLocal(returnUrl:string) = 
    match this.Url.IsLocalUrl(returnUrl) with
    | true -> this.Redirect(returnUrl) :> ActionResult
    | false -> this.RedirectToAction("Index", "Home") :> ActionResult

  member private this.AddErrors(result:IdentityResult) =
    result.Errors
    |> Seq.map (fun error -> this.ModelState.AddModelError("", error))
    |> ignore


//  type ChallengeResult(provider:string, redirectUri:string, userId:string) =
//    inherit HttpUnauthorizedResult()
//      //      public string LoginProvider { get; set; }
//      //      public string RedirectUri { get; set; }
//      //      public string UserId { get; set; }
//
////  internal class ChallengeResult : HttpUnauthorizedResult
////  {
////      public ChallengeResult(string provider, string redirectUri)
////          : this(provider, redirectUri, null)
////      {
////      }
////
////      public ChallengeResult(string provider, string redirectUri, string userId)
////      {
////          LoginProvider = provider;
////          RedirectUri = redirectUri;
////          UserId = userId;
////      }
////
////
////      public override void ExecuteResult(ControllerContext context)
////      {
////          var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
////          if (UserId != null)
////          {
////              properties.Dictionary[XsrfKey] = UserId;
////          }
////          context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
////      }
////  }

  //
  // GET: /Account/Login
  [<AllowAnonymous>]
  member this.Login(returnUrl : string) =
    this.ViewData?ReturnUrl <- returnUrl
    this.View()

  //
  // POST: /Account/Login
  [<HttpPost>]
  [<AllowAnonymous>]
  [<ValidateAntiForgeryToken>]
  member this.Login(model:LoginViewModel, returnUrl:string) =
    match this.ModelState.IsValid with
    | false -> this.View(model) :> ActionResult
    | true -> 
        // This doesn't count login failures towards account lockout
        // To enable password failures to trigger account lockout, change to shouldLockout: true
        let result = 
          async {
            let! passSignIn = this.SignInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, shouldLockout = false)
                              |> Async.AwaitTask
            return passSignIn
          } |> Async.StartAsTask

        match result.Result with
        | SignInStatus.Success -> this.RedirectToLocal(returnUrl)
        | SignInStatus.LockedOut -> this.View("Lockout") :> ActionResult
        | SignInStatus.RequiresVerification -> 
            this.RedirectToAction("SendCode", { ReturnUrl = returnUrl; RememberMe = model.RememberMe }) :> ActionResult
        //| SignInStatus.Failure: this will be caught by the _ match
        | _ -> 
          this.ModelState.AddModelError("", "Invalid login attempt.")
          this.View(model) :> ActionResult
 
  //
  // GET: /Account/VerifyCode
  [<AllowAnonymous>]
  member this.VerifyCode(provider:string, returnUrl:string, rememberMe:bool) =
    // Require that the user has already logged in via username/password or external login
    let hasBeenVerified = 
      async {
        let! verified = this.SignInManager.HasBeenVerifiedAsync()
                        |> Async.AwaitTask
        return verified
      } |> Async.StartAsTask

    match hasBeenVerified.Result with
    | true -> this.View(VerifyCodeViewModel(Provider = provider, ReturnUrl = returnUrl, RememberMe = rememberMe))
    | false -> this.View("Error")
    
  //
  // POST: /Account/VerifyCode
  [<HttpPost>]
  [<AllowAnonymous>]
  [<ValidateAntiForgeryToken>]
  member this.VerifyCode(model:VerifyCodeViewModel) =
    match this.ModelState.IsValid with
    | false -> this.View(model) :> ActionResult
    | true ->
        // The following code protects for brute force attacks against the two factor codes. 
        // If a user enters incorrect codes for a specified amount of time then the user account 
        // will be locked out for a specified amount of time. 
        // You can configure the account lockout settings in IdentityConfig
        let twoFactorSignIn = 
          async {
            let! result = this.SignInManager.TwoFactorSignInAsync(model.Provider, model.Code, isPersistent =  model.RememberMe, rememberBrowser = model.RememberBrowser)
                          |> Async.AwaitTask
            return result
          } |> Async.StartAsTask

        match twoFactorSignIn.Result with
        | SignInStatus.Success -> this.RedirectToLocal(model.ReturnUrl)
        | SignInStatus.LockedOut -> this.View("Lockout") :> ActionResult
        //| SignInStatus.Failure ->  this will be caught by the _ match
        | _ -> 
          this.ModelState.AddModelError("", "Invalid code.")
          this.View(model) :> ActionResult

  //
  // GET: /Account/Register
  [<AllowAnonymous>]
  member this.Register() =
      this.View()

  //
  // POST: /Account/Register
  [<HttpPost>]
  [<AllowAnonymous>]
  [<ValidateAntiForgeryToken>]
  member this.Register(model:RegisterViewModel) =
    let user = ApplicationUser(UserName = model.Email, Email = model.Email)
    let um = 
      async {
        let! result = this.UserManager.CreateAsync(user, model.Password)
                      |> Async.AwaitTask
        return result
      } |> Async.StartAsTask
    
    this.AddErrors(um.Result)

    // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=320771
    // Send an email with this link
    // string code = await UserManager.GenerateEmailConfirmationTokenAsync(user.Id);
    // var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
    // await UserManager.SendEmailAsync(user.Id, "Confirm your account", "Please confirm your account by clicking <a href=\"" + callbackUrl + "\">here</a>");

    if this.ModelState.IsValid && um.Result.Succeeded then
      let signInManager = 
        async {
          let! result = this.SignInManager.SignInAsync(user, isPersistent = false, rememberBrowser = false)
                        |> Async.AwaitIAsyncResult |> Async.Ignore                        
          return result
        } |> Async.StartAsTask
        
      this.RedirectToAction("Index", "Home") :> ActionResult
    else  
      // If we got this far, something failed, redisplay form
      this.View(model) :> ActionResult

  //
  // GET: /Account/ConfirmEmail
  [<AllowAnonymous>]
  member this.ConfirmEmail(userId:string, code:string) =
    match userId, code with
    | null, null -> this.View("Error")
    | _ ->
      let result = 
        async {
          let! confirmEmail = this.UserManager.ConfirmEmailAsync(userId, code)
                              |> Async.AwaitTask
          return confirmEmail
        } |> Async.StartAsTask
            
      let view = match result.Result.Succeeded with
                | true -> "ConfirmEmail"
                | false -> "Error"

      this.View(view)

  //
  // GET: /Account/ForgotPassword
  [<AllowAnonymous>]
  member this.ForgotPassword() =
    this.View()

  //
  // POST: /Account/ForgotPassword
  [<HttpPost>]
  [<AllowAnonymous>]
  [<ValidateAntiForgeryToken>]
  member this.ForgotPassword(model:ForgotPasswordViewModel) =
    
    //TODO: THIS NEEDS WORK!

    match this.ModelState.IsValid with
    | true ->
        let user = 
          async {
            let! result = this.UserManager.FindByNameAsync(model.Email)
                          |> Async.AwaitTask
            return result
          } |> Async.StartAsTask

        let isEmailConfirmed =
          async {
            let! result = this.UserManager.IsEmailConfirmedAsync(user.Result.Id)
                          |> Async.AwaitTask
            return result
          } |> Async.StartAsTask

        match user.Result, isEmailConfirmed.Result with
        | null, false -> this.View("ForgotPasswordConfirmation") :> ActionResult
        // If we got this far, something failed, redisplay form
        | _ -> this.View(model) :> ActionResult        
    // If we got this far, something failed, redisplay form
    | false -> this.View(model) :> ActionResult

    // For more information on how to enable account confirmation and password reset please visit http://go.microsoft.com/fwlink/?LinkID=320771
    // Send an email with this link
    // string code = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
    // var callbackUrl = Url.Action("ResetPassword", "Account", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);		
    // await UserManager.SendEmailAsync(user.Id, "Reset Password", "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>");
    // return RedirectToAction("ForgotPasswordConfirmation", "Account");

  //
  // GET: /Account/ForgotPasswordConfirmation
  [<AllowAnonymous>]
  member this.ForgotPasswordConfirmation() =
    this.View()

  //
  // GET: /Account/ResetPassword
  [<AllowAnonymous>]
  member this.ResetPassword(code:string) =
    match code with
    | null -> this.View("Error")
    | _ -> this.View()
  
  //
  // POST: /Account/ResetPassword
  [<HttpPost>]
  [<AllowAnonymous>]
  [<ValidateAntiForgeryToken>]
  member this.ResetPassword(model:ResetPasswordViewModel) =
    
    //TODO: THIS NEEDS WORK!

    match this.ModelState.IsValid with
    | false -> this.View(model) :> ActionResult
    | true ->
      let user = 
        async {
          let! findByName = this.UserManager.FindByNameAsync(model.Email)
                            |> Async.AwaitTask
          return findByName
        } |> Async.StartAsTask

      match user.Result with
      // Don't reveal that the user does not exist
      | null -> this.RedirectToAction("ResetPasswordConfirmation", "Account") :> ActionResult
      | _ ->
        let result = 
          async {
            let! resetPassword = this.UserManager.ResetPasswordAsync(user.Result.Id, model.Code, model.Password)
                                 |> Async.AwaitTask
            return resetPassword
          } |> Async.StartAsTask
        
        this.AddErrors(result.Result)

        if (result.Result.Succeeded) then
          this.RedirectToAction("ResetPasswordConfirmation", "Account") :> ActionResult
        else
          this.View() :> ActionResult

  //
  // GET: /Account/ResetPasswordConfirmation
  [<AllowAnonymous>]
  member this.ResetPasswordConfirmation() =
      this.View()

  //
  // POST: /Account/ExternalLogin
//  [<HttpPost>]
//  [<AllowAnonymous>]
//  [<ValidateAntiForgeryToken>]
//  member this.ExternalLogin(provider:string, returnUrl:string) =
//    // Request a redirect to the external login provider
//    this.ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", { ReturnUrl = returnUrl }))
//    
