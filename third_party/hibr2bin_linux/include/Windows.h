#ifndef INVESTIGATOR_HIBR2BIN_WINDOWS_COMPAT_H
#define INVESTIGATOR_HIBR2BIN_WINDOWS_COMPAT_H

#include <cstdint>
#include <cwchar>
#include <cstring>

#define _In_
#define _Out_
#define _Inout_

typedef int BOOL;
typedef int BOOLEAN;
typedef void VOID;
typedef std::uint8_t BYTE;
typedef std::uint8_t byte;
typedef std::uint8_t UCHAR;
typedef std::uint16_t USHORT;
typedef std::uint32_t UINT;
typedef std::uint32_t ULONG;
typedef std::uint32_t DWORD;
typedef std::uint64_t ULONG64;
typedef std::uint64_t ULONGLONG;
typedef void *PVOID;
typedef UCHAR *PUCHAR;
typedef BYTE *PBYTE;
typedef ULONG *PULONG;
typedef ULONG64 *PULONG64;
typedef wchar_t WCHAR;
typedef WCHAR *LPWSTR;
typedef const WCHAR *LPCWSTR;
typedef int HANDLE;

typedef struct _COORD {
    short X;
    short Y;
} COORD, *PCOORD;

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#ifndef NULL
#define NULL 0
#endif

#define INVALID_HANDLE_VALUE (-1)
#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define ANYSIZE_ARRAY 1

#define RtlZeroMemory(Destination, Length) std::memset((Destination), 0, (Length))
#define RtlCopyMemory(Destination, Source, Length) std::memcpy((Destination), (Source), (Length))
#define _countof(Array) (sizeof(Array) / sizeof((Array)[0]))
#define _wcsicmp wcscasecmp
#define _wtoi(Value) static_cast<int>(std::wcstol((Value), nullptr, 10))

inline HANDLE GetStdHandle(DWORD) { return 1; }
inline BOOL SetConsoleCursorPosition(HANDLE, COORD) { return TRUE; }
inline DWORD GetLastError() { return 0; }

#endif
