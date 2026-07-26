using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Parsed CDB transcript with marker-delimited sections.</summary>
public sealed record CdbTranscript(
    string Raw,
    IReadOnlyDictionary<CdbProbeSection, string> Sections)
{
    public string Get(CdbProbeSection section) =>
        Sections.TryGetValue(section, out var text) ? text : "";

    public bool Has(CdbProbeSection section) =>
        Sections.TryGetValue(section, out var text) && !string.IsNullOrWhiteSpace(text);
}

/// <summary>
/// Extract <c>RANDFUZZ_*</c> blocks from CDB stdout; regex fallback for legacy transcripts without markers.
/// </summary>
public static class CdbMarkerParser
{
    public static CdbTranscript Parse(string text)
    {
        var sections = new Dictionary<CdbProbeSection, string>();
        foreach (CdbProbeSection section in Enum.GetValues<CdbProbeSection>())
        {
            var block = ExtractBlock(text, CdbMarkers.Begin(section), CdbMarkers.End(section));
            if (!string.IsNullOrWhiteSpace(block))
                sections[section] = block;
        }

        ApplyLegacyFallbacks(text, sections);
        return new CdbTranscript(text, sections);
    }

    public static string ExtractBlock(string text, string beginMarker, string endMarker)
    {
        var lines = new List<string>();
        var started = false;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Contains(beginMarker, StringComparison.Ordinal))
            {
                started = true;
                continue;
            }

            if (line.Contains(endMarker, StringComparison.Ordinal))
                break;
            if (started)
                lines.Add(line);
        }

        return string.Join('\n', lines).Trim();
    }

    public static string ExtractSection(string text, CdbProbeSection section) =>
        ExtractBlock(text, CdbMarkers.Begin(section), CdbMarkers.End(section));

    private static void ApplyLegacyFallbacks(string text, Dictionary<CdbProbeSection, string> sections)
    {
        if (!sections.ContainsKey(CdbProbeSection.Analyze)
            && text.Contains("EXCEPTION_CODE:", StringComparison.OrdinalIgnoreCase))
        {
            sections[CdbProbeSection.Analyze] = text.Trim();
        }
    }
}
