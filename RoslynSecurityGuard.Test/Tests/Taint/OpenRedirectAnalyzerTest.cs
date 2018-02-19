using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers.Taint;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Xml;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests.Taint
{
    [TestClass]
    public class OpenRedirectAnalyzerTest : DiagnosticVerifier
    {

        protected override IEnumerable<DiagnosticAnalyzer> GetDiagnosticAnalyzers()
        {
            return new[] { new TaintAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] {
                MetadataReference.CreateFromFile(typeof(System.Web.HttpResponse).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Http.HttpResponse).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Web.Mvc.ActionResult).Assembly.Location)
            };
        }


        [TestMethod]
        public async Task OpenRedirectFound1()
        {
            var cSharpTest = @"
using System.Web;

class OpenRedirect
{
    public static HttpResponse Response = null;

    public static void Run(string input)
    {
        Response.Redirect(""https://"" + input + ""/home.html"");
    }
}
";
            var visualBasicTest = @"
Imports System.Web

Class OpenRedirect
    Public Shared Response As HttpResponse

	Public Shared Sub Run(input As String)
		Response.Redirect(""https://"" + input + ""/home.html"")
	End Sub
End Class
";
            var expected = new DiagnosticResult
            {
                Id = "SG0036",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task OpenRedirectFound2()
        {
            var cSharpTest = @"
        using System.Web;

        class OpenRedirect
        {
            public static HttpResponse Response = null;

            public static void Run(string input)
            {
                Response.Redirect(input, true);
            }
        }
        ";
            var visualBasicTest = @"
        Imports System.Web

        Class OpenRedirect
            Public Shared Response As HttpResponse

	        Public Shared Sub Run(input As String)
		        Response.Redirect(input, false)
	        End Sub
        End Class
        ";
            var expected = new DiagnosticResult
            {
                Id = "SG0036",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task OpenRedirectFound3()
        {
            var cSharpTest = @"
using Microsoft.AspNetCore.Http;

class OpenRedirect
{
    public static HttpResponse Response = null;

    public static void Run(string input)
    {
        Response.Redirect(input);
    }
}
";
            var visualBasicTest = @"
Imports Microsoft.AspNetCore.Http

Class OpenRedirect
    Public Shared Response As HttpResponse

	Public Shared Sub Run(input As String)
		Response.Redirect(input)
	End Sub
End Class
";
            var expected = new DiagnosticResult
            {
                Id = "SG0036",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task OpenRedirectFound4()
        {
            var cSharpTest = @"
        using Microsoft.AspNetCore.Http;

        class OpenRedirect
        {
            public static HttpResponse Response = null;

            public static void Run(string input)
            {
                Response.Redirect(input, true);
            }
        }
        ";
            var visualBasicTest = @"
        Imports Microsoft.AspNetCore.Http

        Class OpenRedirect
            Public Shared Response As HttpResponse

	        Public Shared Sub Run(input As String)
		        Response.Redirect(input, false)
	        End Sub
        End Class
        ";
            var expected = new DiagnosticResult
            {
                Id = "SG0036",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task OpenRedirectFound5()
        {
            var cSharpTest = @"
using System.Web.Mvc;

class OpenRedirect : Controller
{
    public ActionResult Run(string input)
    {
        return Redirect(input);
    }
}
";
            var visualBasicTest = @"
Imports System.Web.Mvc

Public Class OpenRedirect
    Inherits Controller

	Public Function Run(input As String) as ActionResult
		Return Redirect(input)
	End Function
End Class
";
            var expected = new DiagnosticResult
            {
                Id = "SG0036",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task OpenRedirectFound6()
        {
            var cSharpTest = @"
using System.Web.Mvc;

class OpenRedirect : Controller
{
    public ActionResult Run(string input)
    {
        return RedirectPermanent(input);
    }
}
";
            var visualBasicTest = @"
Imports System.Web.Mvc

Public Class OpenRedirect
    Inherits Controller

	Public Function Run(input As String) as ActionResult
		Return RedirectPermanent(input)
	End Function
End Class
";
            var expected = new DiagnosticResult
            {
                Id = "SG0036",
                Severity = DiagnosticSeverity.Warning,
            };
            await VerifyCSharpDiagnostic(cSharpTest, expected);
            await VerifyVisualBasicDiagnostic(visualBasicTest, expected);
        }

        [TestMethod]
        public async Task OpenRedirectFalsePositive1()
        {
            var cSharpTest = @"
using System.Web;

class OpenRedirect
{
    public static HttpResponse Response = null;

    public static void Run(string input)
    {
        Response.Redirect(""https://example.com/home.html"");
    }
}
";
            var visualBasicTest = @"
Imports System.Web

Class OpenRedirect
    Public Shared Response As HttpResponse

	Public Shared Sub Run(input As String)
		Response.Redirect(""https://example.com/home.html"")
	End Sub
End Class
";

            await VerifyCSharpDiagnostic(cSharpTest);
            await VerifyVisualBasicDiagnostic(visualBasicTest);
        }
    }
}