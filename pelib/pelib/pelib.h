#pragma once

#include <Windows.h>
#include <stdint.h>

namespace pelib
{

    struct ImageSectionHeader
    {
        BYTE Name[8];
        union {
            DWORD PhysicalAddress;
            DWORD VirtualSize;
        } Misc;
        DWORD VirtualAddress;
        DWORD SizeOfRawData;
        DWORD PointerToRawData;
        DWORD PointerToRelocations;
        DWORD PointerToLinenumbers;
        WORD NumberOfRelocations;
        WORD NumberOfLinenumbers;
        DWORD Characteristics;
    };

    class ImageSectionHeaders
    {
    public:
        ImageSectionHeaders(ImageSectionHeader *pBegin, ImageSectionHeader *pEnd) : mBegin(pBegin), mEnd(pEnd) {}

        inline ImageSectionHeader *begin() { return mBegin; }
        inline ImageSectionHeader *end() { return mEnd; }

        inline size_t size() { return mEnd - mBegin; }

        inline ImageSectionHeader *at(size_t i) { return &mBegin[i]; }

    private:
        ImageSectionHeader *mBegin, *mEnd;
    };

    struct ImageDataDirectory
    {
        DWORD VirtualAddress;
        DWORD Size;
    };

    struct ImageOptionalHeader
    {
        //
        // Standard fields.
        //

        WORD Magic;
        BYTE MajorLinkerVersion;
        BYTE MinorLinkerVersion;
        DWORD SizeOfCode;
        DWORD SizeOfInitializedData;
        DWORD SizeOfUninitializedData;
        DWORD AddressOfEntryPoint;
        DWORD BaseOfCode;
        DWORD BaseOfData;

        //
        // NT additional fields.
        //

        DWORD ImageBase;
        DWORD SectionAlignment;
        DWORD FileAlignment;
        WORD MajorOperatingSystemVersion;
        WORD MinorOperatingSystemVersion;
        WORD MajorImageVersion;
        WORD MinorImageVersion;
        WORD MajorSubsystemVersion;
        WORD MinorSubsystemVersion;
        DWORD Win32VersionValue;
        DWORD SizeOfImage;
        DWORD SizeOfHeaders;
        DWORD CheckSum;
        WORD Subsystem;
        WORD DllCharacteristics;
        DWORD SizeOfStackReserve;
        DWORD SizeOfStackCommit;
        DWORD SizeOfHeapReserve;
        DWORD SizeOfHeapCommit;
        DWORD LoaderFlags;
        DWORD NumberOfRvaAndSizes;
        ImageDataDirectory DataDirectory[16];
    };

    struct ImageOptionalHeader64
    {
        WORD Magic;
        BYTE MajorLinkerVersion;
        BYTE MinorLinkerVersion;
        DWORD SizeOfCode;
        DWORD SizeOfInitializedData;
        DWORD SizeOfUninitializedData;
        DWORD AddressOfEntryPoint;
        DWORD BaseOfCode;
        ULONGLONG ImageBase;
        DWORD SectionAlignment;
        DWORD FileAlignment;
        WORD MajorOperatingSystemVersion;
        WORD MinorOperatingSystemVersion;
        WORD MajorImageVersion;
        WORD MinorImageVersion;
        WORD MajorSubsystemVersion;
        WORD MinorSubsystemVersion;
        DWORD Win32VersionValue;
        DWORD SizeOfImage;
        DWORD SizeOfHeaders;
        DWORD CheckSum;
        WORD Subsystem;
        WORD DllCharacteristics;
        ULONGLONG SizeOfStackReserve;
        ULONGLONG SizeOfStackCommit;
        ULONGLONG SizeOfHeapReserve;
        ULONGLONG SizeOfHeapCommit;
        DWORD LoaderFlags;
        DWORD NumberOfRvaAndSizes;
        ImageDataDirectory DataDirectory[16];
    };

    struct ImageFileHeader
    {
        WORD Machine;
        WORD NumberOfSections;
        DWORD TimeDateStamp;
        DWORD PointerToSymbolTable;
        DWORD NumberOfSymbols;
        WORD SizeOfOptionalHeader;
        WORD Characteristics;
    };

    struct ImageNtHeaders
    {
        DWORD Signature;
        ImageFileHeader FileHeader;

        inline ImageSectionHeader *GetFirstSectionHeader()
        {
            return (ImageSectionHeader *)((UINT_PTR)&OptionalHeader + FileHeader.SizeOfOptionalHeader);
        }
        inline ImageSectionHeaders GetSectionHeaders()
        {
            ImageSectionHeader *pFirst = this->GetFirstSectionHeader();
            return ImageSectionHeaders(pFirst, pFirst + FileHeader.NumberOfSections);
        }

        union {
            ImageOptionalHeader OptionalHeader;
            ImageOptionalHeader64 OptionalHeader64;
        };
    };

    struct ImageDosHeader
    {
        static ImageDosHeader *Exact(void *data) { return (ImageDosHeader *)data; }
        static const ImageDosHeader *Exact(const void *data) { return (const ImageDosHeader *)data; }

        WORD e_magic;    // Magic number
        WORD e_cblp;     // Bytes on last page of file
        WORD e_cp;       // Pages in file
        WORD e_crlc;     // Relocations
        WORD e_cparhdr;  // Size of header in paragraphs
        WORD e_minalloc; // Minimum extra paragraphs needed
        WORD e_maxalloc; // Maximum extra paragraphs needed
        WORD e_ss;       // Initial (relative) SS value
        WORD e_sp;       // Initial SP value
        WORD e_csum;     // Checksum
        WORD e_ip;       // Initial IP value
        WORD e_cs;       // Initial (relative) CS value
        WORD e_lfarlc;   // File address of relocation table
        WORD e_ovno;     // Overlay number
        WORD e_res[4];   // Reserved words
        WORD e_oemid;    // OEM identifier (for e_oeminfo)
        WORD e_oeminfo;  // OEM information; e_oemid specific
        WORD e_res2[10]; // Reserved words
        LONG e_lfanew;   // File address of new exe header
    };

    class SectionHeader
    {
    public:
        SectionHeader(void *data) : mData(data){};
        ~SectionHeader(){};

    private:
        void *mData;
    };

    class Image
    {
    public:
        Image(void *data) { mData = data; }
        ~Image() {}

        inline ImageDosHeader *GetDosHeader() { return (ImageDosHeader *)mData; }
        inline ImageNtHeaders *GetNtHeaders() { return (ImageNtHeaders *)((UINT_PTR)mData + GetDosHeader()->e_lfanew); }
        inline ImageFileHeader *GetFileHeader() { return &this->GetNtHeaders()->FileHeader; }
        inline uint32_t GetAddressOfEntryPoint()
        {
            return uint32_t(Is64() ? GetNtHeaders()->OptionalHeader64.AddressOfEntryPoint
                                   : GetNtHeaders()->OptionalHeader.AddressOfEntryPoint);
        }

        inline ImageDataDirectory *GetImageDataDirectory(size_t idx)
        {
            return Is64() ? &GetNtHeaders()->OptionalHeader64.DataDirectory[idx]
                           : &GetNtHeaders()->OptionalHeader.DataDirectory[idx];
        }

        inline void *GetEntryPoint() { return (char *)mData + GetAddressOfEntryPoint(); }

        bool Is64();
        bool Is32();

        size_t GetSectionsCount();
        ImageSectionHeaders GetSectionHeaders();
        ImageSectionHeader *FindSectionHeader(const char *text);

        void *GetSectionRawData(ImageSectionHeader *pHeader);
        void *GetSectionRawDataByVirtualAddress(ImageSectionHeader *pHeader);

    protected:
        void *mData;
    };

    class Image86 : public Image
    {
    public:
        Image86(void *data) : Image(data) {}
        ~Image86() {}

    private:
    };

    class Image64 : public Image
    {
    public:
        Image64(void *data) : Image(data) {}
        ~Image64() {}

    private:
    };
} // namespace pelib
