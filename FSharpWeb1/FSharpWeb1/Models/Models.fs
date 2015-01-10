namespace FSharpWeb1.Models

open System
open System.Collections.Generic
open System.ComponentModel.DataAnnotations
open Microsoft.AspNet.Identity
open Microsoft.Owin.Security

type ExternalLoginConfirmationViewModel() =
  [<Required>]
  [<Display(Name = "Email")>]
  member val Email = String.Empty with get, set

type ExternalLoginListViewModel() =
  member val ReturnUrl = String.Empty with get, set

type SendCodeViewModel() =
  member val SelectedProvider = String.Empty with get, set
  member val Providers = Unchecked.defaultof<ICollection<System.Web.Mvc.SelectListItem>> with get, set
  member val ReturnUrl = String.Empty with get, set
  member val RememberMe = Unchecked.defaultof<bool> with get, set

type VerifyCodeViewModel() =
  [<Required>]
  member val Provider = String.Empty with get, set

  [<Required>]
  [<Display(Name = "Code")>]
  member val Code = String.Empty with get, set

  member val ReturnUrl = String.Empty with get, set
    
  [<Display(Name = "Remember this browser?")>]
  member val RememberBrowser = Unchecked.defaultof<bool> with get, set
  member val RememberMe = Unchecked.defaultof<bool> with get, set

type ForgotViewModel() =
  [<Required>]
  [<Display(Name = "Email")>]
  member val Email = String.Empty with get, set

type LoginViewModel() =
  [<Required>]
  [<Display(Name = "Email")>]
  [<EmailAddress>]
  member val Email = String.Empty with get, set
 
  [<Required>]
  [<DataType(DataType.Password)>]
  [<Display(Name = "Password")>]
  member val Password = String.Empty with get, set

  [<Display(Name = "Remember me?")>]
  member val RememberMe = Unchecked.defaultof<bool> with get, set

type RegisterViewModel() =
  [<Required>]
  [<EmailAddress>]
  [<Display(Name = "Email")>]
  member val Email = String.Empty with get, set

  [<Required>]
  [<StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)>]
  [<DataType(DataType.Password)>]
  [<Display(Name = "Password")>]
  member val Password = String.Empty with get, set

  [<DataType(DataType.Password)>]
  [<Display(Name = "Confirm password")>]
  [<Compare("Password", ErrorMessage = "The password and confirmation password do not match.")>]
  member val ConfirmPassword = String.Empty with get, set

type ResetPasswordViewModel() =
  [<Required>]
  [<EmailAddress>]
  [<Display(Name = "Email")>]
  member val Email = String.Empty with get, set

  [<Required>]
  [<StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)>]
  [<DataType(DataType.Password)>]
  [<Display(Name = "Password")>]
  member val Password = String.Empty with get, set

  [<DataType(DataType.Password)>]
  [<Display(Name = "Confirm password")>]
  [<Compare("Password", ErrorMessage = "The password and confirmation password do not match.")>]
  member val ConfirmPassword = String.Empty with get, set
  
  member val Code = String.Empty with get, set

type ForgotPasswordViewModel() =
  [<Required>]
  [<EmailAddress>]
  [<Display(Name = "Email")>]
  member val Email = String.Empty with get, set

type IndexViewModel() =
  member val HasPassword = Unchecked.defaultof<bool> with get, set
  member val Logins = Unchecked.defaultof<IList<UserLoginInfo>> with get, set
  member val PhoneNumber = String.Empty with get, set
  member val TwoFactor = Unchecked.defaultof<bool> with get, set
  member val BrowserRemembered = Unchecked.defaultof<bool> with get, set

type ManageLoginsViewModel() =
  member val CurrentLogins = Unchecked.defaultof<IList<UserLoginInfo>> with get, set
  member val OtherLogins = Unchecked.defaultof<IList<AuthenticationDescription>> with get, set

type FactorViewModel() =
  member val Purpose = String.Empty with get, set

type SetPasswordViewModel() =
  [<Required>]
  [<StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)>]
  [<DataType(DataType.Password)>]
  [<Display(Name = "New password")>]
  member val NewPassword = String.Empty with get, set

  [<DataType(DataType.Password)>]
  [<Display(Name = "Confirm new password")>]
  [<Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")>]
  member val ConfirmPassword = String.Empty with get, set

type ChangePasswordViewModel() =
  [<Required>]
  [<DataType(DataType.Password)>]
  [<Display(Name = "Current password")>]
  member val OldPassword = String.Empty with get, set

  [<Required>]
  [<StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)>]
  [<DataType(DataType.Password)>]
  [<Display(Name = "New password")>]
  member val NewPassword = String.Empty with get, set

  [<DataType(DataType.Password)>]
  [<Display(Name = "Confirm new password")>]
  [<Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")>]
  member val ConfirmPassword = String.Empty with get, set

type AddPhoneNumberViewModel() =
    [<Required>]
    [<Phone>]
    [<Display(Name = "Phone Number")>]
    member val Number = String.Empty with get, set

type VerifyPhoneNumberViewModel() =
  [<Required>]
  [<Display(Name = "Code")>]
  member val Code = String.Empty with get, set

  [<Required>]
  [<Phone>]
  [<Display(Name = "Phone Number")>]
  member val PhoneNumber = String.Empty with get, set

type ConfigureTwoFactorViewModel() =
  member val SelectedProvider = String.Empty with get, set
  member val Providers = Unchecked.defaultof<ICollection<System.Web.Mvc.SelectListItem>> with get, set