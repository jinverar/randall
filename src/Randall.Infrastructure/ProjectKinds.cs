using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Shared kind predicates so TCP / HTTP / HTTPS share the same send path.</summary>
public static class ProjectKinds
{
    public static bool IsTcpLike(ProjectConfig project) =>
        IsTcpLike(project.Kind) || IsTcpLike(project.Transport.Type);

    public static bool IsTcpLike(string? kind) =>
        kind is not null && (
            kind.Equals("tcp", StringComparison.OrdinalIgnoreCase) ||
            IsHttp(kind));

    public static bool IsHttp(ProjectConfig project) =>
        IsHttp(project.Kind) || IsHttp(project.Transport.Type);

    public static bool IsHttp(string? kind) =>
        kind is not null && (
            kind.Equals("http", StringComparison.OrdinalIgnoreCase) ||
            kind.Equals("https", StringComparison.OrdinalIgnoreCase));

    public static bool IsUdp(ProjectConfig project) =>
        project.Kind.Equals("udp", StringComparison.OrdinalIgnoreCase) ||
        project.Transport.Type.Equals("udp", StringComparison.OrdinalIgnoreCase);

    /// <summary>Normalize http/https aliases onto the TCP tube path (TLS when https).</summary>
    public static void NormalizeTransport(ProjectConfig project)
    {
        if (project.Kind.Equals("https", StringComparison.OrdinalIgnoreCase) ||
            project.Transport.Type.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            project.Transport.Tls = true;
            if (string.IsNullOrWhiteSpace(project.Transport.Type) ||
                project.Transport.Type.Equals("file", StringComparison.OrdinalIgnoreCase) ||
                project.Transport.Type.Equals("tcp", StringComparison.OrdinalIgnoreCase))
                project.Transport.Type = "https";
        }
        else if (project.Kind.Equals("http", StringComparison.OrdinalIgnoreCase) &&
                 (string.IsNullOrWhiteSpace(project.Transport.Type) ||
                  project.Transport.Type.Equals("file", StringComparison.OrdinalIgnoreCase) ||
                  project.Transport.Type.Equals("tcp", StringComparison.OrdinalIgnoreCase)))
        {
            project.Transport.Type = "http";
        }
    }
}
