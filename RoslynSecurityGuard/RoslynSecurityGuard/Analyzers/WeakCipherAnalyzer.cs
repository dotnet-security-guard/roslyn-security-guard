using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System.Collections.Immutable;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class WeakCipherAnalyzer : DiagnosticAnalyzer
    {
        private static ImmutableDictionary<string, DiagnosticDescriptor> Rules =
            new Dictionary<string, DiagnosticDescriptor>
            {
                { "DES", AnalyzerUtil.GetDescriptorFromResource("SG0010", typeof(WeakCipherAnalyzer).Name, DiagnosticSeverity.Warning, "DES") },
                { "RC2", AnalyzerUtil.GetDescriptorFromResource("SG0010", typeof(WeakCipherAnalyzer).Name, DiagnosticSeverity.Warning, "RC2") }
            }.ToImmutableDictionary();

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => Rules.Values.ToImmutableArray<DiagnosticDescriptor>();

        public override void Initialize(AnalysisContext context) => context.RegisterSyntaxNodeAction(VisitSyntaxNode, SyntaxKind.InvocationExpression, SyntaxKind.ObjectCreationExpression);

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            InvocationExpressionSyntax node = ctx.Node as InvocationExpressionSyntax;
            ObjectCreationExpressionSyntax node2 = ctx.Node as ObjectCreationExpressionSyntax;

            if (node != null)
            {
                var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;

                foreach (var cipher in Rules)
                {
                    if (AnalyzerUtil.SymbolMatch(symbol, type: cipher.Key, name: "Create"))
                    {
                        var diagnostic = Diagnostic.Create(cipher.Value, node.Expression.GetLocation(), cipher);
                        ctx.ReportDiagnostic(diagnostic);
                    }
                }
            }
            if (node2 != null)
            {
                var symbol = ctx.SemanticModel.GetSymbolInfo(node2).Symbol;

                foreach (var cipher in Rules)
                {
                    if (AnalyzerUtil.SymbolMatch(symbol, type: cipher.Key+"CryptoServiceProvider"))
                    {
                        var diagnostic = Diagnostic.Create(cipher.Value, node2.GetLocation(), cipher);
                        ctx.ReportDiagnostic(diagnostic);
                    }
                }
            }
        }
    }
}
