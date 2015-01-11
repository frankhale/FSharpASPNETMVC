namespace FSharpWeb1.Controllers

open System
open System.Collections.Generic
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

type ChallengeResult(controller:Controller, provider:string, redirectUri:string, userId:string) = 
  inherit HttpUnauthorizedResult()

  member val private Controller = controller with get, set
  member val LoginProvider = provider with get, set
  member val RedirectUri = redirectUri with get, set
  member val UserId = userId with get, set  

  new(controller:Controller, provider:string, redirectUri:string) = 
    ChallengeResult(controller, provider, redirectUri, null)

  override this.ExecuteResult(context:ControllerContext) =
    let properties = AuthenticationProperties(RedirectUri = this.RedirectUri)    

    match this.UserId with
    | null -> ()
    | _ -> properties.Dictionary.["XsrfId"] <- this.UserId
    
    this.Controller.ControllerContext.HttpContext.GetOwinContext().Authentication.Challenge(properties, this.LoginProvider)

[<Authorize>]
type AccountController(userManager:ApplicationUserManager, signInManager:ApplicationSignInManager) =
  inherit Controller()

  let mutable _signInManager : ApplicationSignInManager = signInManager
  let mutable _userManager : ApplicationUserManager = userManager

  member this.AuthenticationManager with get() = this.HttpContext.GetOwinContext().Authentication

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
            this.RedirectToAction("SendCode", { RouteValues.ReturnUrl = returnUrl; RememberMe = model.RememberMe }) :> ActionResult
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
  [<HttpPost>]
  [<AllowAnonymous>]
  [<ValidateAntiForgeryToken>]
  member this.ExternalLogin(provider:string, returnUrl:string) =
    // Request a redirect to the external login provider
    ChallengeResult(this, provider, this.Url.Action("ExternalLoginCallback", "Account", { ReturnUrl.ReturnUrl = returnUrl }))
   
  //
  // GET: /Account/SendCode
  [<AllowAnonymous>]
  member this.SendCode(returnUrl:string, rememberMe:bool) =
    let userId = 
      async {
        let! result = this.SignInManager.GetVerifiedUserIdAsync()
                      |> Async.AwaitTask
        return result
      } |> Async.StartAsTask

    match userId with
    | null -> this.View("Error")
    | _ -> 
      let userFactors = 
        async {
          let! result = this.UserManager.GetValidTwoFactorProvidersAsync(userId.Result)
                        |> Async.AwaitTask
          return result
        } |> Async.StartAsTask
      let factorOptions = 
          userFactors.Result
          |> Seq.map (fun purpose -> SelectListItem(Text = purpose, Value = purpose))
          |> Seq.toArray :> ICollection<System.Web.Mvc.SelectListItem>                 
      let viewModel = SendCodeViewModel()
      viewModel.Providers <- factorOptions          
      this.View(SendCodeViewModel(Providers = factorOptions, ReturnUrl = returnUrl, RememberMe = rememberMe))
      
  //
  // POST: /Account/SendCode
  [<HttpPost>]
  [<AllowAnonymous>]
  [<ValidateAntiForgeryToken>]
  member this.SendCode(model:SendCodeViewModel) =
      match this.ModelState.IsValid with
      | false -> this.View() :> ActionResult
      | true -> 
        // Generate the token and send it
        let sendTwoFactorCode = 
          async {
            let! result = this.SignInManager.SendTwoFactorCodeAsync(model.SelectedProvider)
                          |> Async.AwaitTask
            return result
          } |> Async.StartAsTask
        
        match sendTwoFactorCode.Result with
        | false -> this.View("Error") :> ActionResult
        | true -> 
            this.RedirectToAction("VerifyCode", { RedirectValues.Provider = model.SelectedProvider; ReturnUrl = model.ReturnUrl; RememberMe = model.RememberMe }) :> ActionResult
            
  //
  // GET: /Account/ExternalLoginCallback
  [<AllowAnonymous>]
  member this.ExternalLoginCallback(returnUrl:string) =
    let loginInfo = 
      async {
        let! result = this.AuthenticationManager.GetExternalLoginInfoAsync()
                      |> Async.AwaitTask
        return result
      } |> Async.StartAsTask

    match loginInfo.Result with
    | null -> this.RedirectToAction("Login") :> ActionResult
    | _ ->
      // Sign in the user with this external login provider if the user already has a login
      let externalSignIn = 
        async {
          let! result = this.SignInManager.ExternalSignInAsync(loginInfo.Result, isPersistent = false)
                        |> Async.AwaitTask
          return result
        } |> Async.StartAsTask

      match externalSignIn.Result with
      | SignInStatus.Success -> this.RedirectToLocal(returnUrl)
      | SignInStatus.LockedOut -> this.View("Lockout") :> ActionResult
      | SignInStatus.RequiresVerification -> this.RedirectToAction("SendCode", { RouteValues.ReturnUrl = returnUrl; RememberMe = false }) :> ActionResult
      //| SignInStatus.Failure: taken care of by the default match
      | _ -> 
        // If the user does not have an account, then prompt the user to create an account
        this.ViewData?ReturnUrl <- returnUrl
        this.ViewData?LoginProvider <- loginInfo.Result.Login.LoginProvider
        this.View("ExternalLoginConfirmation", ExternalLoginConfirmationViewModel(Email = loginInfo.Result.Email)) :> ActionResult

  //
  // POST: /Account/ExternalLoginConfirmation
  [<HttpPost>]
  [<AllowAnonymous>]
  [<ValidateAntiForgeryToken>]
  member this.ExternalLoginConfirmation(model:ExternalLoginConfirmationViewModel, returnUrl:string) =
    
    // TODO: This function needs work and I will be seriously suprised if
    // it even works the way it's currently coded. I got so confused on this
    // function due to it's C# counterpart. This one has stumped me due
    // to the various ways it returns
    
    match this.User.Identity.IsAuthenticated with
    | true -> this.RedirectToAction("Index", "Manage") :> ActionResult
    | false ->
        match this.ModelState.IsValid with
        | false -> 
          this.ViewData?ReturnUrl <- returnUrl
          this.View(model) :> ActionResult
          // Get the information about the user from the external login provider
        | true -> 
            let info = 
              async {
                let! result = this.AuthenticationManager.GetExternalLoginInfoAsync()
                              |> Async.AwaitTask
                return result
              } |> Async.StartAsTask            

            match info.Result with
            | null -> this.View("ExternalLoginFailure") :> ActionResult
            | _ -> 
              let user = ApplicationUser(UserName = model.Email, Email = model.Email)
              let um = 
                async {
                  let! result = this.UserManager.CreateAsync(user)
                                |> Async.AwaitTask
                  return result
                } |> Async.StartAsTask  

              let redirectToLocal : string =
                match um.Result.Succeeded with
                | true ->
                    let addLogin = 
                      async {
                        let! result = this.UserManager.AddLoginAsync(user.Id, info.Result.Login)
                                      |> Async.AwaitTask
                        return result
                      } |> Async.StartAsTask
                
                    match addLogin.Result.Succeeded with
                    | true ->
                        let signIn = 
                          async {
                            let! result = this.SignInManager.SignInAsync(user, isPersistent = false, rememberBrowser = false)
                                          |> Async.AwaitIAsyncResult
                            return result
                          } |> Async.StartAsTask
                        returnUrl
                    | false -> String.Empty
                | false -> String.Empty                    
              
              match redirectToLocal with
              | "" ->
                this.AddErrors(um.Result)
                this.ViewData?ReturnUrl <- returnUrl
                this.View(model) :> ActionResult
              | _ -> this.RedirectToLocal(returnUrl)
              
  //
  // POST: /Account/LogOff
  [<HttpPost>]
  [<ValidateAntiForgeryToken>]
  member this.LogOff() =
    this.AuthenticationManager.SignOut()
    this.RedirectToAction("Index", "Home")

  //
  // GET: /Account/ExternalLoginFailure
  [<AllowAnonymous>]
  member this.ExternalLoginFailure() =
    this.View()

  override this.Dispose(disposing) =
    if disposing then
      match _userManager with
      | null -> ()
      | _ -> 
        _userManager.Dispose()
        _userManager <- null

      match _signInManager with
      | null -> ()
      | _ ->
          _signInManager.Dispose()
          _signInManager <- null

    base.Dispose(disposing)
