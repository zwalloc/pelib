#include <iostream>

#include <fmt/format.h>
#include <futile/futile.h>
#include <pelib/pelib.h>
#include <ulib/runtimeerror.h>

int main()
{
    try
    {
        auto data = futile::open("test.exe", "rb").read<ulib::buffer>();
        pelib::Image image(data.data());

        if (!image.Is64())
            throw ulib::RuntimeError{"required x64 test.exe"};

        fmt::print("Entry point: 0x{:X}\n", image.GetAddressOfEntryPoint());

        auto ntHeaders = image.GetNtHeaders();
        for (auto &obj : ntHeaders->GetSectionHeaders())
        {
            fmt::print("Section: {}\n", (char *)obj.Name);
        }

        auto relocEntry = image.GetImageDataDirectory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
        if (relocEntry->VirtualAddress)
        {
            fmt::print("Reloc VA: {}, Size: {}.\n", relocEntry->VirtualAddress, relocEntry->Size);
        }
        else
        {
            fmt::print("No relocations\n");
        }

        auto importsEntry = image.GetImageDataDirectory(IMAGE_DIRECTORY_ENTRY_IMPORT);
        if (importsEntry->VirtualAddress)
        {
            fmt::print("Imports VA: {}, Size: {}.\n", importsEntry->VirtualAddress, importsEntry->Size);
        }
        else
        {
            fmt::print("No imports\n");
        }
    }
    catch (const std::exception &ex)
    {
        fmt::print("exception: {}\n", ex.what());
    }

    return 0;
}
