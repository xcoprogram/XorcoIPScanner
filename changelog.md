# Xorco IP Scanner Changelog

## [v1.0.6] - 2026-03-07
### Added
- **Expanded Device Identification**: Implemented custom mDNS (Multicast DNS) and NetBIOS responders to resolve `.local` and legacy hostnames more effectively.
- **MAC Manufacturer Lookup**: Integrated a vendor OUI database to identify hardware manufacturers (Apple, HP, Sonos, etc.) even when hostnames are missing.
- **Web Interface Discovery**: Added a feature to fetch `<title>` tags from open web ports (80, 443) to help identify routers, printers, and IoT devices.

### Changed
- Improved language compatibility for older .NET Framework compilers (replaced C# 6.0 interpolation with `string.Format`).
- Renamed "Hostname" column to "Hostname / Manufacturer" for richer discovery data.
- Renamed "Latency" column to "Ping Response (ms)" for better clarity.

## [v1.0.5] - 2026-03-07
### Changed
- Performance optimization: Refined multi-threaded scan logic for faster host discovery.
- UI bug fix: Corrected column alignment on high-DPI displays.


## [v1.0.4] - 2026-03-07
### Changed
- Improved default sorting: scan results are now automatically sorted by IP address.
- Added a final sort trigger upon scan completion to ensure logical ordering.

## [v1.0.3] - 2026-03-07
### Added
- **SSH Username Prompt**: When opening an SSH connection, the app now prompts for a custom username (defaults to current Windows user).

## [v1.0.2] - 2026-03-07
### Added
- **Branding**: Renamed application to "Xorco IP Scanner".
- **Resizable UI**: Implemented a draggable splitter between the Network Interface list and the Scan Settings.
- **Improved List Visibility**: Set the DNS column to auto-expand and fixed layout "stickiness" issues.

## [v1.0.0] - 2026-03-07
### Added
- **Multi-Interface Support**: Display multiple active adapters (Ethernet, Wi-Fi, VPN) simultaneously.
- **Real-time Monitoring**: Interface list now updates automatically when network cables are plugged/unplugged.
- **Network Discovery**: Added Gateway (Router) and DNS server addresses to the interface list.
- **Custom Scan Ranges**: Users can now manually set Start and End IP addresses for scanning.
- **Export Options**: Added "Export to CSV" and "Export to PDF" features.
- **Scan Timer**: Added real-time "Estimated Remaining Time" countdown during scans.
- **UI Overhaul**: Expanded settings area and improved overall high-DPI scaling/readability.
- **Context Menu Integration**: Right-click on found hosts to Open HTTP, HTTPS, RDP, or SSH.
