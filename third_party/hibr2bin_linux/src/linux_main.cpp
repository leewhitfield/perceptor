#include "precomp.h"

#include <clocale>
#include <cstdlib>
#include <string>
#include <vector>

static std::wstring widen(const char *value)
{
    if (!value) return {};
    std::mbstate_t state {};
    const char *src = value;
    size_t len = std::mbsrtowcs(nullptr, &src, 0, &state);
    if (len == static_cast<size_t>(-1)) {
        std::wstring fallback;
        for (const unsigned char *p = reinterpret_cast<const unsigned char *>(value); *p; ++p) {
            fallback.push_back(static_cast<wchar_t>(*p));
        }
        return fallback;
    }
    std::wstring result(len, L'\0');
    state = std::mbstate_t {};
    src = value;
    std::mbsrtowcs(result.data(), &src, result.size(), &state);
    return result;
}

static bool arg_eq(const std::wstring &arg, const wchar_t *long_name, const wchar_t *short_name)
{
    return _wcsicmp(arg.c_str(), long_name) == 0 || _wcsicmp(arg.c_str(), short_name) == 0;
}

static void help()
{
    wprintf(L"Usage: hibr2bin-linux /PLATFORM X64|X86 /MAJOR <n> /MINOR <n> /INPUT <hiberfil.sys> /OUTPUT <out.bin> [/OFFSET <hex>]\n");
}

int main(int argc, char **argv)
{
    std::setlocale(LC_ALL, "");
    std::vector<std::wstring> args;
    args.reserve(argc);
    for (int i = 0; i < argc; ++i) args.push_back(widen(argv[i]));

    PROGRAM_ARGUMENTS parsed {};
    for (int i = 1; i < argc; ++i) {
        const std::wstring &arg = args[i];
        if (arg_eq(arg, L"/PLATFORM", L"/P") || arg_eq(arg, L"-PLATFORM", L"-P")) {
            if (++i >= argc) break;
            parsed.HasPlatform = TRUE;
            if (_wcsicmp(args[i].c_str(), L"X64") == 0) parsed.Platform = PlatformX64;
            else if (_wcsicmp(args[i].c_str(), L"X86") == 0) parsed.Platform = PlatformX86;
            else parsed.HasPlatform = FALSE;
        } else if (arg_eq(arg, L"/MAJOR", L"/V") || arg_eq(arg, L"-MAJOR", L"-V")) {
            if (++i >= argc) break;
            parsed.MajorVersion = _wtoi(args[i].c_str());
            parsed.HasMajorVersion = TRUE;
        } else if (arg_eq(arg, L"/MINOR", L"/M") || arg_eq(arg, L"-MINOR", L"-M")) {
            if (++i >= argc) break;
            parsed.MinorVersion = _wtoi(args[i].c_str());
            parsed.HasMinorVersion = TRUE;
        } else if (arg_eq(arg, L"/OFFSET", L"/L") || arg_eq(arg, L"-OFFSET", L"-L")) {
            if (++i >= argc) break;
            wchar_t *end = nullptr;
            parsed.DataOffset = std::wcstoull(args[i].c_str(), &end, 16);
            parsed.HasDataOffset = TRUE;
        } else if (arg_eq(arg, L"/INPUT", L"/I") || arg_eq(arg, L"-INPUT", L"-I")) {
            if (++i >= argc) break;
            parsed.FileName = args[i].data();
        } else if (arg_eq(arg, L"/OUTPUT", L"/O") || arg_eq(arg, L"-OUTPUT", L"-O")) {
            if (++i >= argc) break;
            parsed.OutFileName = args[i].data();
        } else if (_wcsicmp(arg.c_str(), L"/?") == 0 || _wcsicmp(arg.c_str(), L"/HELP") == 0 || _wcsicmp(arg.c_str(), L"--help") == 0) {
            help();
            return 0;
        }
    }

    if (!parsed.HasPlatform || !parsed.HasMajorVersion || !parsed.HasMinorVersion || !parsed.FileName || !parsed.OutFileName) {
        help();
        return 1;
    }

    MemoryBlock *memory_blocks = NULL;
    BOOLEAN result = FALSE;
    if (ProcessHiberfil(&parsed, &memory_blocks)) {
        result = WriteMemoryBlocksToDisk(memory_blocks, &parsed);
    }
    delete memory_blocks;
    return result ? 0 : 1;
}
