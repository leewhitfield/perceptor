#include "precomp.h"

#include <cstdarg>

static void vprint_wide(LPCWSTR format, va_list args)
{
    vwprintf(format, args);
}

USHORT GetConsoleTextAttribute(HANDLE)
{
    return 0;
}

VOID Red(LPCWSTR Format, ...)
{
    va_list va;
    va_start(va, Format);
    vprint_wide(Format, va);
    va_end(va);
}

VOID White(LPCWSTR Format, ...)
{
    va_list va;
    va_start(va, Format);
    vprint_wide(Format, va);
    va_end(va);
}

VOID Green(LPCWSTR Format, ...)
{
    va_list va;
    va_start(va, Format);
    vprint_wide(Format, va);
    va_end(va);
}

VOID GetCursorPosition(HANDLE, PCOORD Coord)
{
    Coord->X = 0;
    Coord->Y = 0;
}

BOOLEAN CryptInitSha256(VOID)
{
    return TRUE;
}

BOOLEAN CryptHashData(PVOID, ULONG)
{
    return TRUE;
}

BYTE *CryptGetHash()
{
    return NULL;
}

ULONG CryptGetHashLen()
{
    return 0;
}

VOID CryptClose()
{
}
