# Project Structure

## Top-Level Organization

```
7-Zip/
├── Asm/           # Assembly optimizations
├── C/             # ANSI-C implementation (LZMA SDK)
├── CPP/           # C++ implementation (full 7-Zip)
├── DOC/           # Documentation
└── .kiro/         # Kiro configuration
```

## Assembly Code (`Asm/`)

Platform-specific optimized implementations:
- `arm/`: ARM 32-bit assembly
- `arm64/`: ARM 64-bit assembly (GNU syntax)
- `x86/`: x86/x64 assembly (MASM syntax)
  - CRC, AES, SHA-1, SHA-256, LZMA decoding, sorting

## C Implementation (`C/`)

Pure C code for maximum portability (LZMA SDK):

**Core compression**:
- `LzmaDec.c/h`, `LzmaEnc.c/h`: LZMA codec
- `Lzma2Dec.c/h`, `Lzma2Enc.c/h`: LZMA2 codec
- `LzFind.c/h`: Match finder for compression
- `Ppmd*.c/h`: PPMd compression

**Archive handling**:
- `7z*.c/h`: 7z format decoder
- `Xz*.c/h`: XZ format support

**Utilities**:
- `Alloc.c/h`: Memory allocation
- `Threads.c/h`: Threading support
- `CpuArch.c/h`: CPU feature detection

**Crypto**:
- `Aes.c/h`, `Sha*.c/h`: Cryptographic functions

**Build files**:
- `*.mak`: Makefiles for various compilers/platforms
- `Util/`: Standalone utilities (7z, Lzma, SfxSetup)

## C++ Implementation (`CPP/`)

### Common (`CPP/Common/`)

Shared utilities and base classes:
- String handling: `MyString.cpp/h`, `StringConvert.cpp/h`
- Containers: `MyVector.cpp/h`, `MyMap.cpp/h`
- I/O streams: `StdInStream.cpp/h`, `StdOutStream.cpp/h`
- Hash registration: `*Reg.cpp` (CRC, MD5, SHA variants)

### Windows (`CPP/Windows/`)

Windows-specific abstractions (also work on Unix via compatibility layer):
- File operations: `FileIO.cpp/h`, `FileFind.cpp/h`, `FileDir.cpp/h`
- System: `DLL.cpp/h`, `Registry.cpp/h`, `Thread.h`
- UI: `Window.cpp/h`, `Menu.cpp/h`, `Control/`

### 7zip Core (`CPP/7zip/`)

**Archive handlers** (`Archive/`):
- Each format has its own handler (e.g., `7z/`, `Zip/`, `Tar/`, `Rar/`)
- `IArchive.h`: Archive interface definition
- `Common/`: Shared archive utilities

**Compression codecs** (`Compress/`):
- Individual codec implementations
- Filters (BCJ, Delta, etc.)

**Crypto** (`Crypto/`):
- Encryption/decryption implementations
- Hash functions

**Common** (`Common/`):
- Core 7-Zip utilities
- Stream abstractions
- Progress callbacks

**UI** (`UI/`):
- `Console/`: Command-line interface (7z.exe)
- `FileManager/`: GUI file manager (7zFM.exe)
- `GUI/`: GUI version (7zG.exe)
- `Explorer/`: Shell extension (7-zip.dll)
- `Common/`: Shared UI code

**Bundles** (`Bundles/`):
- Standalone executables combining multiple modules
- Each subdirectory is a build target with its own makefile

## Coding Conventions

### Header Guards

Use `ZIP7_INC_` prefix:
```c
#ifndef ZIP7_INC_FILENAME_H
#define ZIP7_INC_FILENAME_H
```

### Naming

- **Types**: PascalCase (e.g., `ISeqInStream`, `CLookToRead2`)
- **Functions**: PascalCase (e.g., `LzmaEncode`, `SeqInStream_Read`)
- **Macros**: UPPER_SNAKE_CASE with `Z7_` prefix (e.g., `Z7_STDCALL`, `Z7_FORCE_INLINE`)
- **Constants**: PascalCase with `k` prefix (e.g., `kSignature`)

### Platform Abstraction

- Use `7zTypes.h` types: `Byte`, `UInt32`, `UInt64`, `SRes`, `WRes`
- Use `Z7_` prefixed macros for compiler/platform specifics
- Use `EXTERN_C_BEGIN`/`EXTERN_C_END` for C/C++ compatibility

### Error Handling

- C code: Return `SRes` (0 = success, non-zero = error)
- Use `RINOK(x)` macro to propagate errors
- Windows: `WRes` for system errors, converted via `MY_SRes_HRESULT_FROM_WRes`

### Precompiled Headers

- C++: `StdAfx.h` (includes `Common.h`)
- C: `Precomp.h` (project-specific)

### Memory Management

- Use `ISzAlloc` interface for custom allocators
- Separate temporary and main memory pools in decoders

## Build Output

Default output directory: `_o/` (or platform-specific like `x64/`, `x86/`)
