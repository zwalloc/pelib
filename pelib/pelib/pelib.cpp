#include "pelib.h"

#include <Windows.h>

namespace pelib
{
	bool Image::Is64() { return this->GetFileHeader()->Machine == IMAGE_FILE_MACHINE_AMD64; }
	bool Image::Is32() { return this->GetFileHeader()->Machine == IMAGE_FILE_MACHINE_I386; }

	size_t Image::GetSectionsCount() { return this->GetFileHeader()->NumberOfSections; }

	ImageSectionHeaders Image::GetSectionHeaders() { return this->GetNtHeaders()->GetSectionHeaders(); }

	ImageSectionHeader* Image::FindSectionHeader(const char* text)
	{
		for (auto& it : GetSectionHeaders())
		{
			if (strcmp((char*)it.Name, text) == 0)
				return &it;
		}

		return nullptr;
	}

	void* Image::GetSectionRawData(ImageSectionHeader* pHeader)
	{
		return (void*)((UINT_PTR)mData + pHeader->PointerToRawData);
	}

	void* Image::GetSectionRawDataByVirtualAddress(ImageSectionHeader* pHeader)
	{
		return (void*)((UINT_PTR)mData + pHeader->VirtualAddress);
	}

}