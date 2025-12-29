# Product Overview

7-Zip is a file archiver with high compression ratio, primarily for Windows but also supporting Linux/macOS.

## Key Features

- Supports multiple archive formats: 7z, XZ, BZIP2, GZIP, TAR, ZIP, WIM, and more
- LZMA/LZMA2 compression provides high compression ratios
- Open source under GNU LGPL (with BSD 3-clause for some components)
- Available as GUI, console, and library implementations

## Components

- **7z.exe**: Console version with all formats
- **7za.exe**: Standalone console (7z/xz/cab/zip/gzip/bzip2/tar only)
- **7zr.exe**: Reduced standalone (7z only)
- **7zFM.exe**: File Manager GUI
- **7z.dll**: Format handler DLL
- **LZMA SDK**: Public domain compression library

## License Notes

- Core 7-Zip: GNU LGPL
- LZMA SDK: Public domain
- unRAR code: Restricted license - cannot be used to recreate RAR compression algorithm
- Use `DISABLE_RAR=1` or `DISABLE_RAR_COMPRESS=1` build flags to exclude RAR code if needed

## Version

Current version: 25.01 (as of documentation)
