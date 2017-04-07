using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using System.Collections.Generic;
using TestHelper;
//using System.Text.Encodings.Web;
//using Microsoft.AspNetCore.Authorization;
//using Microsoft.AspNetCore.Mvc;

namespace RoslynSecurityGuard.Test.Tests
{
    [TestClass]
    public class XssPreventionAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new XssPreventionAnalyzer() };
        }

        // Referencing AspNetCore assemblies gives
        // error CS0012: The type 'Object' is defined in an assembly that is not referenced. You must add a reference to assembly 'System.Runtime, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a'.
        //protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        //{
        //    return new[]
        //    {
        //        MetadataReference.CreateFromFile(typeof(HttpGetAttribute).Assembly.Location),
        //        MetadataReference.CreateFromFile(typeof(HtmlEncoder).Assembly.Location),
        //        MetadataReference.CreateFromFile(typeof(Controller).Assembly.Location),
        //        MetadataReference.CreateFromFile(typeof(AllowAnonymousAttribute).Assembly.Location),
        //    };
        //}

        #region Tests that are producing diagnostics

        [TestMethod]
        public void unencodedSensibleData()
        {
            var test = @"
            using Microsoft.AspNetCore.Mvc;

            namespace VulnerableApp
            {
                public class TestController : Controller
                {
                    [HttpGet(""{sensibleData}"")]
                    public string Get(int sensibleData)
                    {
                        return ""value "" + sensibleData;
                    }
                }
            }
            ";
            var expected = new DiagnosticResult
            {
                Id = "SG0029",
                Severity = DiagnosticSeverity.Warning
            };

            VerifyCSharpDiagnostic(test, expected, verifyIfCompiles: false);
        }

        #endregion

        #region Tests that are not producing diagnostics

        [TestMethod]
        public void encodedSensibleDataWithTemporaryVariable()
        {
            var test = @"
            using Microsoft.AspNetCore.Mvc;
            using System.Text.Encodings.Web;

            namespace VulnerableApp
            {
                public class TestController : Controller
                {
                    [HttpGet(""{sensibleData}"")]
                    public string Get(string sensibleData)
                    {
                        string temporary_variable = HtmlEncoder.Default.Encode(sensibleData);
                        return ""value "" + temporary_variable;
                    }
                }
            }
            ";

            VerifyCSharpDiagnostic(test, verifyIfCompiles: false);
        }

        [TestMethod]
        public void encodedSensibleDataOnReturn()
        {
            var test = @"
            using Microsoft.AspNetCore.Mvc;
            using System.Text.Encodings.Web;

            namespace VulnerableApp
            {
                public class TestController : Controller
                {
                    [HttpGet(""{sensibleData}"")]
                    public string Get(string sensibleData)
                    {
                        return ""value "" + HtmlEncoder.Default.Encode(sensibleData);
                    }
                }
            }
            ";

            VerifyCSharpDiagnostic(test, verifyIfCompiles: false);
        }

        [TestMethod]
        public void returnEncodedData()
        {
            var test = @"
            using Microsoft.AspNetCore.Mvc;
            using System.Text.Encodings.Web;

            namespace VulnerableApp
            {
                public class TestController : Controller
                {
                    [HttpGet(""{sensibleData}"")]
                    public string Get(string sensibleData)
                    {
                        return HtmlEncoder.Default.Encode(""value "" + sensibleData);
                    }
                }
            }
            ";

            VerifyCSharpDiagnostic(test, verifyIfCompiles: false);
        }

        [TestMethod]
        public void encodedDataWithSameVariableUsage()
        {
            var test = @"
            using Microsoft.AspNetCore.Mvc;
            using System.Text.Encodings.Web;

            namespace VulnerableApp
            {
                public class TestController : Controller
                {
                    [HttpGet(""{sensibleData}"")]
                    public string Get(string sensibleData)
                    {
                        sensibleData = HtmlEncoder.Default.Encode(""value "" + sensibleData);
                        return ""value "" + HtmlEncoder.Default.Encode(sensibleData);
                    }
                }
            }
            ";

            VerifyCSharpDiagnostic(test, verifyIfCompiles:false);
        }

        [TestMethod]
        public void methodWithOtherReturningTypeThanString()
        {
            var test = @"
            using Microsoft.AspNetCore.Mvc;
            using Microsoft.AspNetCore.Authorization;

            namespace VulnerableApp
            {
                public class TestController : Controller
                {
                    [AllowAnonymous]
                    public ActionResult Login(string returnUrl)
                    {
                        ViewBag.ReturnUrl = returnUrl;
                        return View();
                    }
                }
            }
            ";

            VerifyCSharpDiagnostic(test, verifyIfCompiles: false);
        }

        [TestMethod]
        public void privateMethod()
        {
            var test = @"
            using Microsoft.AspNetCore.Mvc;

            namespace VulnerableApp
            {
                public class TestController : Controller
                {
                    [HttpGet(""{sensibleData}"")]
                    private string Get(int sensibleData)
                    {
                        return ""value "" + sensibleData;
                    }
                }
            }
            ";

            VerifyCSharpDiagnostic(test, verifyIfCompiles: false);
        }

        #endregion
    }
}
