using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System.Collections.Generic;
using System.Collections.Immutable;

namespace RoslynSecurityGuard.Analyzers
{
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public class WeakHashingAnalyzer : DiagnosticAnalyzer
    {
        private static ImmutableDictionary<string, DiagnosticDescriptor> Rules =
            new Dictionary<string, DiagnosticDescriptor>
            {
                { "MD5", AnalyzerUtil.GetDescriptorFromResource("SG0006", typeof(WeakHashingAnalyzer).Name, DiagnosticSeverity.Warning, "MD5") },
                { "SHA1", AnalyzerUtil.GetDescriptorFromResource("SG0006", typeof(WeakHashingAnalyzer).Name, DiagnosticSeverity.Warning, "SHA1") }
            }.ToImmutableDictionary();

        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => Rules.Values.ToImmutableArray();

        public override void Initialize(AnalysisContext context) => context.RegisterSyntaxNodeAction(VisitSyntaxNode, SyntaxKind.InvocationExpression);

        private static void VisitSyntaxNode(SyntaxNodeAnalysisContext ctx)
        {
            var node = ctx.Node as InvocationExpressionSyntax;
            if (node == null) return;

            var symbol = ctx.SemanticModel.GetSymbolInfo(node).Symbol;

            foreach (var r in Rules)
            {
                if (AnalyzerUtil.SymbolMatch(symbol, type: r.Key, name: "Create"))
                {
                    var diagnostic = Diagnostic.Create(r.Value, node.Expression.GetLocation(), r.Key);
                    ctx.ReportDiagnostic(diagnostic);
                }
            }
        }
    }
}