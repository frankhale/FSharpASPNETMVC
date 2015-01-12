namespace FSharpWeb1.Controllers

open System
open System.Linq
open System.Threading.Tasks
open System.Web
open System.Web.Mvc
open Microsoft.AspNet.Identity
open Microsoft.AspNet.Identity.Owin
open Microsoft.Owin.Security

open FSharpWeb1.Infrastructure
open FSharpWeb1.Infrastructure.Helpers
open FSharpWeb1.Models

type ManageMessageId =
  | AddPhoneSuccess
  | ChangePasswordSuccess
  | SetTwoFactorSuccess
  | SetPasswordSuccess
  | RemoveLoginSuccess
  | RemovePhoneSuccess
  | Error

[<Authorize>]
type ManageController(userManager:ApplicationUserManager, signInManager:ApplicationSignInManager) =
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

  //
  // GET: /Manage/Index
  member this.Index(message:ManageMessageId) =
    this.ViewData?StatusMessage <-
      match message with
        | ManageMessageId.ChangePasswordSuccess -> "Your password has been changed."
        | ManageMessageId.SetPasswordSuccess -> "Your password has been set."
        | ManageMessageId.SetTwoFactorSuccess -> "Your two-factor authentication provider has been set."
        | ManageMessageId.Error -> "An error has occurred."
        | ManageMessageId.AddPhoneSuccess -> "Your phone number was added."
        | ManageMessageId.RemovePhoneSuccess -> "Your phone number was removed."
        | _ -> ""    
    
    let userId = this.User.Identity.GetUserId()
    let model = new IndexViewModel()
    model.HasPassword <- this.HasPassword()
    
    // TODO...

    //PhoneNumber = await UserManager.GetPhoneNumberAsync(userId)
    //TwoFactor = await UserManager.GetTwoFactorEnabledAsync(userId)
    //Logins = await UserManager.GetLoginsAsync(userId)
    //BrowserRemembered = await AuthenticationManager.TwoFactorBrowserRememberedAsync(userId)

    this.View(model)


  member private this.AddErrors(result:IdentityResult) =
    result.Errors
    |> Seq.map(fun error -> this.ModelState.AddModelError("", error))

  member private this.HasPassword() =
    let user = this.UserManager.FindById(this.User.Identity.GetUserId())
    match user with
    | null -> false
    | _ -> 
      match String.IsNullOrEmpty(user.PasswordHash) with
      | false -> true
      | _ -> false

  member private this.HasPhoneNumber() =
    let user = this.UserManager.FindById(this.User.Identity.GetUserId())
    match user with
    | null -> false
    | _ -> 
      match String.IsNullOrEmpty(user.PhoneNumber) with
      | false -> true
      | _ -> false

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
