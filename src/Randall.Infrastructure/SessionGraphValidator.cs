using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Validate and visualize boofuzz-style sessionGraph (s_switch) definitions.</summary>
public static class SessionGraphValidator
{
    public static SessionGraphReportDto Validate(ProjectConfig project, string yamlPath)
    {
        var graph = project.SessionGraph;
        var commands = SessionGraph.LoadCommands(project, yamlPath);
        var commandNames = commands.Select(c => c.Name).ToList();

        if (graph is null)
        {
            return new SessionGraphReportDto(
                project.Name,
                false,
                true,
                [],
                [],
                "",
                null,
                null,
                [],
                commandNames,
                "");
        }

        var errors = new List<string>();
        var warnings = new List<string>();
        var byName = commands.ToDictionary(c => c.Name, StringComparer.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(graph.Start))
            errors.Add("sessionGraph.start is required");
        else if (!byName.ContainsKey(graph.Start))
            errors.Add($"sessionGraph.start '{graph.Start}' is not a session command");

        if (!string.IsNullOrWhiteSpace(graph.Mutate) && !byName.ContainsKey(graph.Mutate))
            errors.Add($"sessionGraph.mutate '{graph.Mutate}' is not a session command");

        var edgeRows = new List<SessionGraphEdgeDto>();
        foreach (var edge in graph.Edges)
        {
            if (string.IsNullOrWhiteSpace(edge.From))
                errors.Add("sessionGraph edge missing 'from'");
            else if (!byName.ContainsKey(edge.From))
                errors.Add($"edge from '{edge.From}' is not a session command");

            if (string.IsNullOrWhiteSpace(edge.To))
                errors.Add("sessionGraph edge missing 'to'");
            else if (!byName.ContainsKey(edge.To))
                errors.Add($"edge to '{edge.To}' is not a session command");

            if (string.IsNullOrWhiteSpace(edge.When))
                warnings.Add($"edge {edge.From}→{edge.To} has empty 'when' — matches any response");

            edgeRows.Add(new SessionGraphEdgeDto(edge.From, edge.When ?? "", edge.To));
        }

        if (graph.Edges.Count == 0)
            warnings.Add("sessionGraph has no edges — graph mode will not branch");

        var reachable = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(graph.Start))
            Walk(graph.Start, graph.Edges, reachable);

        foreach (var cmd in commands)
        {
            if (!reachable.Contains(cmd.Name) &&
                !cmd.Name.Equals(graph.Start, StringComparison.OrdinalIgnoreCase))
                warnings.Add($"command '{cmd.Name}' is unreachable from start '{graph.Start}'");
        }

        var mermaid = BuildMermaid(graph);
        return new SessionGraphReportDto(
            project.Name,
            true,
            errors.Count == 0,
            errors,
            warnings,
            mermaid,
            graph.Start,
            graph.Mutate,
            edgeRows,
            commandNames,
            BuildYamlSnippet(graph));
    }

    private static void Walk(string node, IReadOnlyList<SessionGraphEdgeConfig> edges, HashSet<string> visited)
    {
        if (!visited.Add(node))
            return;
        foreach (var edge in edges.Where(e => e.From.Equals(node, StringComparison.OrdinalIgnoreCase)))
            Walk(edge.To, edges, visited);
    }

    private static string BuildYamlSnippet(SessionGraphConfig graph)
    {
        var sb = new StringBuilder();
        sb.AppendLine("sessionGraph:");
        sb.AppendLine($"  start: {graph.Start}");
        if (!string.IsNullOrWhiteSpace(graph.Mutate))
            sb.AppendLine($"  mutate: {graph.Mutate}");
        sb.AppendLine("  edges:");
        foreach (var edge in graph.Edges)
            sb.AppendLine($"    - {{ from: {edge.From}, when: \"{edge.When}\", to: {edge.To} }}");
        return sb.ToString().TrimEnd();
    }

    private static string BuildMermaid(SessionGraphConfig graph)
    {
        if (graph.Edges.Count == 0)
            return "";

        var sb = new StringBuilder();
        sb.AppendLine("graph LR");
        if (!string.IsNullOrWhiteSpace(graph.Start))
            sb.AppendLine($"  start([start]) --> {SanitizeId(graph.Start)}");
        if (!string.IsNullOrWhiteSpace(graph.Mutate))
            sb.AppendLine($"  style {SanitizeId(graph.Mutate)} fill:#f96,stroke:#333");

        foreach (var edge in graph.Edges)
        {
            var label = string.IsNullOrWhiteSpace(edge.When) ? "?" : edge.When.Replace("\"", "'");
            sb.AppendLine($"  {SanitizeId(edge.From)} -->|{label}| {SanitizeId(edge.To)}");
        }

        return sb.ToString().TrimEnd();
    }

    private static string SanitizeId(string name) =>
        name.Replace('-', '_').Replace(' ', '_');
}
