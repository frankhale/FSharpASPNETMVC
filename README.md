#FSharpASPNETMVC

A straight port of the C# ASP.NET MVC 5 project template to F#

##Description

I created a new F# MVC 5 project using the F# MVC 5 templates available in the
Visual Studio Gallery and then I created a new C# ASP.NET MVC 5 project with 
individual logon accounts and then ported it to F#. I copied the assets over
like Javascript, CSS, etc.. and then ported the C# code to F#.

##Status

The initial port is more than half way complete but some of the code is rough
and probably not idiomatic.  

###Done:
- Web.config
- Scripts
- Contents
- Startup.cs
- Stuff in App_Start
- Models
  
###TODO:
- Finish controllers  
	-	First pass through the AccountController is done but the code is not exactly where I want it yet
- Copy over all the views and make sure they are wired up correctly

##License

GNU GPL v2