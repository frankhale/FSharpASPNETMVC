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
    model.PhoneNumber <- await(this.UserManager.GetPhoneNumberAsync(userId))
    model.TwoFactor <- await(this.UserManager.GetTwoFactorEnabledAsync(userId))
    model.Logins <- await(this.UserManager.GetLoginsAsync(userId))
    model.BrowserRemembered <- await(this.AuthenticationManager.TwoFactorBrowserRememberedAsync(userId))

    this.View(model)

  //
  // POST: /Manage/RemoveLogin
  [<HttpPost>]
  [<ValidateAntiForgeryToken>]
  member this.RemoveLogin(loginProvider:string, providerKey:string) =
    let result = await(this.UserManager.RemoveLoginAsync(this.User.Identity.GetUserId(), UserLoginInfo(loginProvider, providerKey)))
    let message = 
      match result.Succeeded with
      | true -> 
          let user = await(this.UserManager.FindByIdAsync(this.User.Identity.GetUserId()))
          match user with
          | null -> ManageMessageId.Error
          | _ ->
            awaitPlainTask(this.SignInManager.SignInAsync(user, isPersistent = false, rememberBrowser = false))
            ManageMessageId.RemoveLoginSuccess;
      | false -> ManageMessageId.Error
    
    this.RedirectToAction("ManageLogins", { Message = message })

  //
  // GET: /Manage/AddPhoneNumber
  member this.AddPhoneNumber() =
    this.View()

  //
  // POST: /Manage/AddPhoneNumber
  [<HttpPost>]
  [<ValidateAntiForgeryToken>]
  member this.AddPhoneNumber(model:AddPhoneNumberViewModel) =
    match this.ModelState.IsValid with
    | false -> this.View(model) :> ActionResult
    | true ->
        // Generate the token and send it
        let code = await(this.UserManager.GenerateChangePhoneNumberTokenAsync(this.User.Identity.GetUserId(), model.Number))
        if this.UserManager.SmsService <> null then
          let message = new IdentityMessage()
          message.Destination <- model.Number
          message.Body <- "Your security code is: " + code
          awaitPlainTask(this.UserManager.SmsService.SendAsync(message))

        this.RedirectToAction("VerifyPhoneNumber", { PhoneNumber.PhoneNumber = model.Number }) :> ActionResult

  //
  // POST: /Manage/EnableTwoFactorAuthentication
  [<HttpPost>]
  [<ValidateAntiForgeryToken>]
  member this.EnableTwoFactorAuthentication() =
    await(this.UserManager.SetTwoFactorEnabledAsync(this.User.Identity.GetUserId(), true)) |> ignore
    let user = await(this.UserManager.FindByIdAsync(this.User.Identity.GetUserId()))
    if user <> null then
      awaitPlainTask(this.SignInManager.SignInAsync(user, isPersistent = false, rememberBrowser = false))

    this.RedirectToAction("Index", "Manage")

  //
  // POST: /Manage/DisableTwoFactorAuthentication
  [<HttpPost>]
  [<ValidateAntiForgeryToken>]
  member this.DisableTwoFactorAuthentication() =
    await(this.UserManager.SetTwoFactorEnabledAsync(this.User.Identity.GetUserId(), false)) |> ignore
    let user = await(this.UserManager.FindByIdAsync(this.User.Identity.GetUserId()))
    if user <> null then
      awaitPlainTask(this.SignInManager.SignInAsync(user, isPersistent = false, rememberBrowser = false))

    this.RedirectToAction("Index", "Manage")

  //
  // GET: /Manage/VerifyPhoneNumber
  member this.VerifyPhoneNumber(phoneNumber:string) =
      let code = await(this.UserManager.GenerateChangePhoneNumberTokenAsync(this.User.Identity.GetUserId(), phoneNumber))
      // Send an SMS through the SMS provider to verify the phone number
      match String.IsNullOrEmpty(phoneNumber) with
      | true -> this.View("Error")
      | false ->
          this.View(VerifyPhoneNumberViewModel(PhoneNumber = phoneNumber))

  //
  // POST: /Manage/VerifyPhoneNumber
  [<HttpPost>]
  [<ValidateAntiForgeryToken>]
  member this.VerifyPhoneNumber(model:VerifyPhoneNumberViewModel) =
    
    //TODO: This needs work!

    match this.ModelState.IsValid with
    | false -> this.View(model) :> ActionResult
    | true ->
        let result = await(this.UserManager.ChangePhoneNumberAsync(this.User.Identity.GetUserId(), model.PhoneNumber, model.Code))
        match result.Succeeded with
        | true -> 
            let user = await(this.UserManager.FindByIdAsync(this.User.Identity.GetUserId()))
            match user with
            | null ->
              this.ModelState.AddModelError("", "Failed to verify phone")
              this.View(model) :> ActionResult
            | _ ->
              awaitPlainTask(this.SignInManager.SignInAsync(user, isPersistent = false, rememberBrowser = false))
              this.RedirectToAction("Index", { Message.Message = ManageMessageId.AddPhoneSuccess }) :> ActionResult
        | false ->
          // If we got this far, something failed, redisplay form
          this.ModelState.AddModelError("", "Failed to verify phone")
          this.View(model) :> ActionResult

  member private this.AddErrors(result:IdentityResult) =
    result.Errors
    |> Seq.map(fun error -> this.ModelState.AddModelError("", error))

  //
  // GET: /Manage/RemovePhoneNumber
  member this.RemovePhoneNumber() =
    let result = await(this.UserManager.SetPhoneNumberAsync(this.User.Identity.GetUserId(), null))
    match result.Succeeded with
    | false -> this.RedirectToAction("Index", { Message.Message = ManageMessageId.Error })
    | true ->   
        let user = await(this.UserManager.FindByIdAsync(this.User.Identity.GetUserId()))
        if user <> null then
          awaitPlainTask(this.SignInManager.SignInAsync(user, isPersistent = false, rememberBrowser = false))

        this.RedirectToAction("Index", { Message.Message = ManageMessageId.RemovePhoneSuccess })

  //
  // GET: /Manage/ChangePassword
  member this.ChangePassword() =
    this.View()

  //
  // POST: /Manage/ChangePassword
  [<HttpPost>]
  [<ValidateAntiForgeryToken>]
  member this.ChangePassword(model:ChangePasswordViewModel) =
    match this.ModelState.IsValid with
    | false -> this.View(model) :> ActionResult
    | true ->
      let result = await(this.UserManager.ChangePasswordAsync(this.User.Identity.GetUserId(), model.OldPassword, model.NewPassword))
      match result.Succeeded with
      | false -> 
        this.AddErrors(result) |> ignore
        this.View(model) :> ActionResult
      | true -> 
        let user = await(this.UserManager.FindByIdAsync(this.User.Identity.GetUserId()))
        match user with
        | null -> 
          this.AddErrors(result) |> ignore
          this.View(model) :> ActionResult
        | _ ->
          awaitPlainTask(this.SignInManager.SignInAsync(user, isPersistent = false, rememberBrowser = false))
          this.RedirectToAction("Index", { Message.Message = ManageMessageId.ChangePasswordSuccess }) :> ActionResult

  //
  // GET: /Manage/SetPassword
  member this.SetPassword() =
    this.View()

  //
  // POST: /Manage/SetPassword
//  [HttpPost]
//  [ValidateAntiForgeryToken]
//  public async Task<ActionResult> SetPassword(SetPasswordViewModel model)
//  {
//      if (ModelState.IsValid)
//      {
//          var result = await UserManager.AddPasswordAsync(User.Identity.GetUserId(), model.NewPassword);
//          if (result.Succeeded)
//          {
//              var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
//              if (user != null)
//              {
//                  await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
//              }
//              return RedirectToAction("Index", new { Message = ManageMessageId.SetPasswordSuccess });
//          }
//          AddErrors(result);
//      }
//
//      // If we got this far, something failed, redisplay form
//      return View(model);
//  }

//  //
//  // GET: /Manage/ManageLogins
//  public async Task<ActionResult> ManageLogins(ManageMessageId? message)
//  {
//      ViewBag.StatusMessage =
//          message == ManageMessageId.RemoveLoginSuccess ? "The external login was removed."
//          : message == ManageMessageId.Error ? "An error has occurred."
//          : "";
//      var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
//      if (user == null)
//      {
//          return View("Error");
//      }
//      var userLogins = await UserManager.GetLoginsAsync(User.Identity.GetUserId());
//      var otherLogins = AuthenticationManager.GetExternalAuthenticationTypes().Where(auth => userLogins.All(ul => auth.AuthenticationType != ul.LoginProvider)).ToList();
//      ViewBag.ShowRemoveButton = user.PasswordHash != null || userLogins.Count > 1;
//      return View(new ManageLoginsViewModel
//      {
//          CurrentLogins = userLogins,
//          OtherLogins = otherLogins
//      });
//  }
//
//  //
//  // POST: /Manage/LinkLogin
//  [HttpPost]
//  [ValidateAntiForgeryToken]
//  public ActionResult LinkLogin(string provider)
//  {
//      // Request a redirect to the external login provider to link a login for the current user
//      return new AccountController.ChallengeResult(provider, Url.Action("LinkLoginCallback", "Manage"), User.Identity.GetUserId());
//  }
//
//  //
//  // GET: /Manage/LinkLoginCallback
//  public async Task<ActionResult> LinkLoginCallback()
//  {
// let XsrfKey = "XsrfId"
//      var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync(XsrfKey, User.Identity.GetUserId());
//      if (loginInfo == null)
//      {
//          return RedirectToAction("ManageLogins", new { Message = ManageMessageId.Error });
//      }
//      var result = await UserManager.AddLoginAsync(User.Identity.GetUserId(), loginInfo.Login);
//      return result.Succeeded ? RedirectToAction("ManageLogins") : RedirectToAction("ManageLogins", new { Message = ManageMessageId.Error });
//  }

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
