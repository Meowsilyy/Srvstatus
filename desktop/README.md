# ServerStatus Desktop

ServerStatus Desktop is a native Windows version of the existing ServerStatus lookup tool.

It keeps the website lookup areas for overview, infrastructure, TCP services, HTTP, edge/CDN detection, network data, DNS, TLS, security headers, registration, email DNS, technology fingerprints, Minecraft status, site files and raw JSON.

The desktop build adds deeper IP intelligence and routing views including multi-source IP geolocation with confidence, reverse DNS, ASN and network ownership, IP RDAP, RIPEstat routing data, RPKI validation, PeeringDB data, Tor exit detection, ping, packet loss, jitter, traceroute, public reputation sources and optional enrichment from AbuseIPDB, Shodan and VirusTotal.

IP geolocation is approximate network intelligence. Returned coordinates can represent a city centroid, ISP point of presence or datacenter and are not presented as an exact device or building location.

Cloudflare and other edge providers are detected from public network and response information. The app does not attempt protected-origin discovery or bypass CDN protections.

## Build

Install the .NET 8 SDK on Windows and run:

```text
dotnet build ServerStatusApp.csproj -c Release
```

For a portable self-contained Windows x64 build:

```text
dotnet publish ServerStatusApp.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishReadyToRun=true -o publish
```

The published executable can be moved and launched from any normal writable location such as Desktop or Downloads. Settings are stored separately under the current Windows user's LocalAppData folder.

## Optional API keys

The app works without paid keys. The Settings panel accepts optional keys for ipapi.is, AbuseIPDB, Shodan and VirusTotal. Missing providers do not abort a lookup; provider results are independent and the raw responses remain visible in the report.
