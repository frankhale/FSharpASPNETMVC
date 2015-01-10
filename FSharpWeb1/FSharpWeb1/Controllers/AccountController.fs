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

  member this.RedirectToLocal(returnUrl:string) = 
    match this.Url.IsLocalUrl(returnUrl) with
    | true -> this.Redirect(returnUrl) :> ActionResult
    | false -> this.RedirectToAction("Index", "Home") :> ActionResult

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
    // This doesn't count login failures towards account lockout
    // To enable password failures to trigger account lockout, change to shouldLockout: true
    let result = 
      async {
        let! passSignIn = this.SignInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, shouldLockout = false)
                          |> Async.AwaitTask
        return passSignIn
      } |> Async.StartAsTask
  
    match this.ModelState.IsValid with
    | false -> this.View(model) :> ActionResult
    | true -> 
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

    match this.ModelState.IsValid with
    | false -> this.View(model) :> ActionResult
    | true ->
        match twoFactorSignIn.Result with
        | SignInStatus.Success -> this.RedirectToLocal(model.ReturnUrl)
        | SignInStatus.LockedOut -> this.View("Lockout") :> ActionResult
        //| SignInStatus.Failure ->  this will be caught by the _ match
        | _ -> 
          this.ModelState.AddModelError("", "Invalid code.")
          this.View(model) :> ActionResult
