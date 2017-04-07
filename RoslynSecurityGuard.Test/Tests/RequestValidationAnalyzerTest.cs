using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RoslynSecurityGuard.Analyzers;
using System.Collections.Generic;
using System.Web.Mvc;
using TestHelper;

namespace RoslynSecurityGuard.Test.Tests
{
    [TestClass]
    public class RequestValidationAnalyzerTest : DiagnosticVerifier
    {
        protected override IEnumerable<DiagnosticAnalyzer> GetCSharpDiagnosticAnalyzers()
        {
            return new[] { new RequestValidationAnalyzer() };
        }

        protected override IEnumerable<MetadataReference> GetAdditionnalReferences()
        {
            return new[] { MetadataReference.CreateFromFile(typeof(ValidateInputAttribute).Assembly.Location) };
        }

        [TestMethod]
        public void DetectAnnotationValidateInput()
        {
            var test = @"
using System.Web.Mvc;

namespace VulnerableApp
{
    public class TestController
    {
        [HttpPost]
        [ValidateInput(false)]
        public ActionResult ControllerMethod(string input) {

            return null;
        }
    }
}
";

            var expected = new DiagnosticResult
            {
                Id = "SG0017",
                Severity = DiagnosticSeverity.Warning
            };
            VerifyCSharpDiagnostic(test,expected);
        }

        [ValidateInput(false)]
        public ActionResult ControllerMethod(string input)
        {
            return null;
        }
    }
}
