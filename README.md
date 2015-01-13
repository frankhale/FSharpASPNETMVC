#FSharpASPNETMVC

A straight port of the C# ASP.NET MVC 5 project template to F#

##Description

I created a new F# MVC 5 project using the F# MVC 5 templates available in the
Visual Studio Gallery and then I created a new C# ASP.NET MVC 5 project with 
individual logon accounts and then ported it to F#. I copied the assets over
like Javascript, CSS, etc.. and then ported the C# code to F#.

##Status

The initial pass through all of the code has been done and everything is ported
but everything is has not been tested yet (specifically registering an account
and logging in).  

I'm going to say up front that I think all the async/await C# interop code is
currently broke because I don't fully understand how to deal with C# 
async/await in F#. Currently registering a user works but logging in does not
and there are a lot of async/await calls with respect to the AccountController.

If anyone can help me understand this I'd really appreciate it! Pull requests
are very welcome!!!

###Done:
- Web.config
- Scripts
- Contents
- Startup.cs
- Stuff in App_Start
- Models
- Controllers
- Views
  
##License

GNU GPL v2