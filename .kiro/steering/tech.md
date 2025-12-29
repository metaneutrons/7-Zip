# Technology Stack

## Languages

- **C**: Core compression/decompression algorithms, LZMA SDK
- **C++**: Archive handlers, UI components, high-level functionality
- **Assembly**: Optimized implementations for CRC, SHA, AES, LZMA decoding
  - x86/x64: MASM syntax (use asmc, UASM, or JWasm assemblers on Linux)
  - ARM64: GNU assembler syntax

## Build Systems

### Windows (MSVC/nmake)

**Compilers**: Visual Studio 2017/2019/2022, or older versions (MSVC 6.0, Windows SDK)

**Build via makefile**:
```bash
cd CPP/7zip/Bundles/<target>
nmake
```

**Platform options**: Set `PLATFORM` to x64, x86, arm64, arm, or ia64

**Common flags**:
- `OLD_COMPILER=1`: For MSVC 6.0 and older
- `MY_DYNAMIC_LINK=1`: Link to msvcrt.dll dynamically

**Assembler**: Requires ml.exe (x86) or ml64.exe (x64) from Windows SDK

### Linux/macOS (GCC/Clang/make)

**Build commands**:
```bash
cd CPP/7zip/Bundles/Alone2

# Basic build (no assembly optimization)
make -j -f makefile.gcc

# With GCC (no assembly)
make -j -f ../../cmpl_gcc.mak

# With Clang (no assembly)
make -j -f ../../cmpl_clang.mak

# x64 with assembly (requires asmc or UASM)
make -j -f ../../cmpl_gcc_x64.mak

# ARM64 with assembly
make -j -f ../../cmpl_gcc_arm64.mak

# macOS ARM64
make -j -f ../../cmpl_mac_arm64.mak
```

**Build flags**:
- `DISABLE_RAR=1`: Remove all RAR code
- `DISABLE_RAR_COMPRESS=1`: Remove RAR decompression codecs only
- `USE_JWASM=1`: Use JWasm instead of asmc (note: JWasm lacks AES support)
- `IS_X64=1 USE_ASM=1 MY_ASM=<path>`: Specify custom assembler

**Dependencies**:
- GCC or Clang compiler
- make
- Optional: asmc or UASM for x86/x64 assembly optimization
- pthread and dl libraries (Linux)

## Key Directories

- `C/`: ANSI-C implementation (LZMA SDK, 7z decoder)
- `CPP/`: C++ implementation (full 7-Zip)
- `Asm/`: Assembly optimizations (arm, arm64, x86)
- `CPP/7zip/Bundles/`: Executable targets
- `CPP/7zip/Archive/`: Archive format handlers
- `CPP/7zip/Compress/`: Compression codecs
- `CPP/7zip/Crypto/`: Encryption implementations

## Compilation Targets

Common build targets in `CPP/7zip/Bundles/`:
- `Alone`: 7za.exe (standalone, limited formats)
- `Alone2`: 7zz.exe (standalone, all formats)
- `Alone7z`: 7zr.exe (7z only)
- `Format7zF`: 7z.dll (all formats)
- `LzmaCon`: lzma.exe (LZMA utility)
- `SFXCon`: 7zCon.sfx (console SFX module)
- `SFXWin`: 7z.sfx (Windows SFX module)

## Preprocessor Defines

- `UNICODE`, `_UNICODE`: Unicode support (default on Windows)
- `_REENTRANT`: Thread-safe code
- `_FILE_OFFSET_BITS=64`: Large file support
- `Z7_ST`: Single-threaded build
- `Z7_LZMA_DEC_OPT`: Use optimized LZMA decoder
- `NDEBUG`: Release build
