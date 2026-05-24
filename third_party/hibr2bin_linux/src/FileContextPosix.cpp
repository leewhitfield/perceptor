#include "precomp.h"

#include <cerrno>
#include <clocale>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

static std::string narrow_path(LPCWSTR value)
{
    if (!value) return {};
    std::mbstate_t state{};
    const wchar_t *src = value;
    size_t len = std::wcsrtombs(nullptr, &src, 0, &state);
    if (len == static_cast<size_t>(-1)) {
        std::string fallback;
        for (const wchar_t *p = value; *p; ++p) fallback.push_back(static_cast<char>(*p & 0xff));
        return fallback;
    }
    std::string result(len, '\0');
    state = std::mbstate_t{};
    src = value;
    std::wcsrtombs(result.data(), &src, result.size(), &state);
    return result;
}

static int fd_from_handle(HANDLE handle)
{
    return handle - 1;
}

static HANDLE handle_from_fd(int fd)
{
    return fd < 0 ? INVALID_HANDLE_VALUE : fd + 1;
}

BOOLEAN FileContext::Is64Bits()
{
    return GetPlatform() == PlatformX64;
}

BOOLEAN FileContext::IsWin10()
{
    return (GetMajorVersion() == 10) && (GetMinorVersion() == 0);
}

BOOLEAN FileContext::IsWin81()
{
    return (GetMajorVersion() == 6) && (GetMinorVersion() == 3);
}

BOOLEAN FileContext::IsWin8()
{
    return (GetMajorVersion() == 6) && (GetMinorVersion() == 2);
}

BOOLEAN FileContext::IsWin7()
{
    return (GetMajorVersion() == 6) && (GetMinorVersion() == 1);
}

BOOLEAN FileContext::IsWinVista()
{
    return (GetMajorVersion() == 6) && (GetMinorVersion() == 0);
}

BOOLEAN FileContext::IsWinXP64()
{
    return (GetMajorVersion() == 5) && (GetMinorVersion() == 2) && Is64Bits();
}

BOOLEAN FileContext::IsWinXP()
{
    return (GetMajorVersion() == 5) && (GetMinorVersion() == 1);
}

BOOLEAN FileContext::IsVistaAndAbove()
{
    return GetMajorVersion() >= 6;
}

BOOLEAN FileContext::IsWin7AndAbove()
{
    return (GetMajorVersion() > 6) || ((GetMajorVersion() == 6) && (GetMinorVersion() >= 1));
}

BOOLEAN FileContext::IsWin8AndAbove()
{
    return (GetMajorVersion() > 6) || ((GetMajorVersion() == 6) && (GetMinorVersion() >= 2));
}

PVOID FileContext::GetTempBuffer()
{
    if (m_PreAllocatedBuffer == NULL) m_PreAllocatedBuffer = new BYTE[m_PreAllocatedBufferSize];
    RtlZeroMemory(m_PreAllocatedBuffer, m_PreAllocatedBufferSize);
    return m_PreAllocatedBuffer;
}

PVOID FileContext::ReadFile(ULONG64 Offset, ULONG DataBufferSize, PVOID *DataBuffer)
{
    PVOID Buffer = NULL;
    if (DataBuffer == NULL) {
        if (m_ReadedDataSize < DataBufferSize) {
            delete[] static_cast<BYTE *>(m_ReadedData);
            m_ReadedData = NULL;
            m_ReadedDataSize = 0;
        }
        if (m_ReadedData == NULL) {
            m_ReadedData = new BYTE[DataBufferSize];
            m_ReadedDataSize = DataBufferSize;
        }
        Buffer = m_ReadedData;
    } else {
        if (*DataBuffer == NULL) *DataBuffer = new BYTE[DataBufferSize];
        Buffer = *DataBuffer;
    }

    RtlZeroMemory(Buffer, DataBufferSize);
    ssize_t read_bytes = pread(fd_from_handle(GetFileHandle()), Buffer, DataBufferSize, static_cast<off_t>(Offset));
    if (read_bytes < 0) return NULL;
    return Buffer;
}

BOOLEAN FileContext::OpenFile(LPCWSTR FileName, ULONG)
{
    std::setlocale(LC_ALL, "");
    std::string path = narrow_path(FileName);
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    m_FileHandle = handle_from_fd(fd);
    return m_FileHandle != INVALID_HANDLE_VALUE;
}

BOOLEAN FileContext::CreateOutputFile(LPWSTR FileName)
{
    std::setlocale(LC_ALL, "");
    std::string path = narrow_path(FileName);
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    m_OutFileHandle = handle_from_fd(fd);
    return m_OutFileHandle != INVALID_HANDLE_VALUE;
}

BOOLEAN FileContext::WriteFile(PVOID Buffer, DWORD NbOfBytesToWrite)
{
    BYTE *cursor = static_cast<BYTE *>(Buffer);
    DWORD remaining = NbOfBytesToWrite;
    int fd = fd_from_handle(m_OutFileHandle);
    while (remaining > 0) {
        ssize_t written = write(fd, cursor, remaining);
        if (written < 0) {
            if (errno == EINTR) continue;
            return FALSE;
        }
        if (written == 0) return FALSE;
        cursor += written;
        remaining -= static_cast<DWORD>(written);
    }
    return TRUE;
}

VOID FileContext::Close()
{
    if (m_FileHandle && m_FileHandle != INVALID_HANDLE_VALUE) {
        close(fd_from_handle(m_FileHandle));
        m_FileHandle = NULL;
    }
    if (m_OutFileHandle && m_OutFileHandle != INVALID_HANDLE_VALUE) {
        close(fd_from_handle(m_OutFileHandle));
        m_OutFileHandle = NULL;
    }
}

FileContext::~FileContext()
{
    Close();
    delete[] static_cast<BYTE *>(m_ReadedData);
    delete[] static_cast<BYTE *>(m_PreAllocatedBuffer);
}

ULONGLONG FileContext::GetFileSize()
{
    struct stat st {};
    if (fstat(fd_from_handle(m_FileHandle), &st) != 0) return 0;
    return static_cast<ULONGLONG>(st.st_size);
}
