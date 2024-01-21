#include "PE64File.h"

PE64File::PE64File(char* arg_name, FILE* arg_pefile) {

	pfName = arg_name;
	pfPEFile = arg_pefile;

	ParseFile();

}

DWORD PE64File::GetOffset(DWORD arg_va) {

	for (int i = 0; i < pfNTHeaders.FileHeader.NumberOfSections; i++)
	{
		if (arg_va >= pfSectionHeaders[i].VirtualAddress
			&& arg_va < (pfSectionHeaders[i].VirtualAddress + pfSectionHeaders[i].Misc.VirtualSize))
		{
			return (arg_va - pfSectionHeaders[i].VirtualAddress) + pfSectionHeaders[i].PointerToRawData;
		}
	}

}

char* PE64File::GetName(DWORD arg_va) {

	DWORD lNameOffset = GetOffset(arg_va);
	int lNameSize = 0;

	while (true)
	{
		char lTmp;

		fseek(pfPEFile, (lNameOffset + lNameSize), SEEK_SET);
		fread(&lTmp, sizeof(char), 1, pfPEFile);

		if (lTmp == 0x00)
		{
			break;
		}

		lNameSize++;
	}

	char* lName = new char[lNameSize + 1];

	fseek(pfPEFile, lNameOffset, SEEK_SET);
	fread(lName, (lNameSize * sizeof(char)) + 1, 1, pfPEFile);

	return lName;

}

void PE64File::ParseDOSHeader() {

	fseek(pfPEFile, 0, SEEK_SET);
	fread(&pfDOSHeader, sizeof(IMAGE_DOS_HEADER), 1, pfPEFile);

}

void PE64File::ParseNTHeaders() {

	fseek(pfPEFile, pfDOSHeader.e_lfanew, SEEK_SET);
	fread(&pfNTHeaders, sizeof(pfNTHeaders), 1, pfPEFile);

	pfExportDirectory = pfNTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	pfImportDirectory = pfNTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	pfResourceDirectory = pfNTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	pfExceptionDirectory = pfNTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	pfSecurityDirectory = pfNTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	pfBaseRelocDirectory = pfNTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	pfDebugDirectory = pfNTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	pfArchitectureDirectory = pfNTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE];
	pfGlobalPTRDirectory = pfNTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR];
	pfTLSDirectory = pfNTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	pfLoadConfigDirectory = pfNTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	pfBoundImportDirectory = pfNTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
	pfIATDirectory = pfNTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
	pfDelayImportDirectory = pfNTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	pfComDescriptorDirectory = pfNTHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];

}

void PE64File::ParseSectionHeaders() {

	pfSectionHeaders = new IMAGE_SECTION_HEADER[pfNTHeaders.FileHeader.NumberOfSections];
	DWORD lOffset = pfDOSHeader.e_lfanew + sizeof(pfNTHeaders);
	
	for (int i = 0; i < pfNTHeaders.FileHeader.NumberOfSections; i++)
	{
		fseek(pfPEFile, lOffset, SEEK_SET);
		fread(&pfSectionHeaders[i], sizeof(IMAGE_SECTION_HEADER), 1, pfPEFile);

		lOffset += sizeof(IMAGE_SECTION_HEADER);
	}

}

void PE64File::ParseExportDirectory() {

	if (pfExportDirectory.Size == 0)
	{
		return;
	}

	fseek(pfPEFile, GetOffset(pfExportDirectory.VirtualAddress), SEEK_SET);
	fread(&pfExportTable, sizeof(IMAGE_EXPORT_DIRECTORY), 1, pfPEFile);

	pfExportAddressTable = new DWORD[pfExportTable.NumberOfFunctions];
	pfExportNamePointerTable = new DWORD[pfExportTable.NumberOfNames];
	pfExportOrdinalTable = new WORD[pfExportTable.NumberOfNames];

	fseek(pfPEFile, GetOffset(pfExportTable.AddressOfFunctions), SEEK_SET);
	fread(pfExportAddressTable, sizeof(DWORD) * pfExportTable.NumberOfFunctions, 1, pfPEFile);

	fseek(pfPEFile, GetOffset(pfExportTable.AddressOfNames), SEEK_SET);
	fread(pfExportNamePointerTable, sizeof(DWORD) * pfExportTable.NumberOfNames, 1, pfPEFile);

	fseek(pfPEFile, GetOffset(pfExportTable.AddressOfNameOrdinals), SEEK_SET);
	fread(pfExportOrdinalTable, sizeof(WORD) * pfExportTable.NumberOfNames, 1, pfPEFile);

}

void PE64File::ParseImportDirectory() {

	if (pfImportDirectory.Size == 0)
	{
		return;
	}

	DWORD lOffset = GetOffset(pfImportDirectory.VirtualAddress);
	pfImportDirectoryCount = 0;

	while (true)
	{
		IMAGE_IMPORT_DESCRIPTOR lTemp;

		fseek(pfPEFile, lOffset, SEEK_SET);
		fread(&lTemp, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, pfPEFile);

		if (lTemp.Name == 0x00000000 && lTemp.FirstThunk == 0x00000000)
		{
			break;
		}

		lOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		pfImportDirectoryCount++;
	}

	pfImportTable = new IMAGE_IMPORT_DESCRIPTOR[pfImportDirectoryCount];

	lOffset = GetOffset(pfImportDirectory.VirtualAddress);

	for (int i = 0; i < pfImportDirectoryCount; i++)
	{
		fseek(pfPEFile, lOffset, SEEK_SET);
		fread(&pfImportTable[i], sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, pfPEFile);

		lOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

}

void PE64File::ParseFile() {

	ParseDOSHeader();
	ParseNTHeaders();
	ParseSectionHeaders();
	ParseExportDirectory();
	ParseImportDirectory();

}

void PE64File::PrintFileInfo() {

	printf(" File\n");
	printf(" ----------------------------------\n");
	printf(" Property\t| Value\n");
	printf(" ----------------------------------\n");

	printf(" File Name\t| %s\n", pfName);
	printf(" File Type\t| Portable Executable 64\n");

	printf(" ----------------------------------\n\n");

}

void PE64File::PrintDOSHeaderInfo() {

	DWORD lOffset = 0;

	printf(" DOS Header\n");
	printf(" ----------------------------------\n");
	printf(" Member\t\t| Offset\t| Size\t| Value\n");
	printf(" ----------------------------------\n");

	printf(" e_magic\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfDOSHeader.e_magic);
	lOffset += sizeof(pfDOSHeader.e_magic);

	printf(" e_cblp\t\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfDOSHeader.e_cblp);
	lOffset += sizeof(pfDOSHeader.e_cblp);

	printf(" e_cp\t\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfDOSHeader.e_cp);
	lOffset += sizeof(pfDOSHeader.e_cp);

	printf(" e_crlc\t\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfDOSHeader.e_crlc);
	lOffset += sizeof(pfDOSHeader.e_crlc);

	printf(" e_cparhdr\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfDOSHeader.e_cparhdr);
	lOffset += sizeof(pfDOSHeader.e_cparhdr);

	printf(" e_minalloc\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfDOSHeader.e_minalloc);
	lOffset += sizeof(pfDOSHeader.e_minalloc);

	printf(" e_maxalloc\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfDOSHeader.e_maxalloc);
	lOffset += sizeof(pfDOSHeader.e_maxalloc);

	printf(" e_ss\t\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfDOSHeader.e_ss);
	lOffset += sizeof(pfDOSHeader.e_ss);

	printf(" e_sp\t\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfDOSHeader.e_sp);
	lOffset += sizeof(pfDOSHeader.e_sp);

	printf(" e_csum\t\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfDOSHeader.e_csum);
	lOffset += sizeof(pfDOSHeader.e_csum);

	printf(" e_ip\t\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfDOSHeader.e_ip);
	lOffset += sizeof(pfDOSHeader.e_ip);

	printf(" e_cs\t\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfDOSHeader.e_cs);
	lOffset += sizeof(pfDOSHeader.e_cs);

	printf(" e_lfarlc\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfDOSHeader.e_lfarlc);
	lOffset += sizeof(pfDOSHeader.e_lfarlc);

	printf(" e_ovno\t\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfDOSHeader.e_ovno);
	lOffset += sizeof(pfDOSHeader.e_ovno);

	for (int i = 0; i < 4; i++)
	{
		printf(" e_res[%d]\t| 0x%08X\t| WORD\t| 0x%04X\n", i, lOffset, pfDOSHeader.e_res[i]);
		lOffset += sizeof(pfDOSHeader.e_res[i]);
	}

	printf(" e_oemid\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfDOSHeader.e_oemid);
	lOffset += sizeof(pfDOSHeader.e_oemid);

	printf(" e_oeminfo\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfDOSHeader.e_oeminfo);
	lOffset += sizeof(pfDOSHeader.e_oeminfo);

	for (int i = 0; i < 10; i++)
	{
		printf(" e_res2[%d]\t| 0x%08X\t| WORD\t| 0x%04X\n", i, lOffset, pfDOSHeader.e_res2[i]);
		lOffset += sizeof(pfDOSHeader.e_res2[i]);
	}

	printf(" e_lfanew\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfDOSHeader.e_lfanew);
	lOffset += sizeof(pfDOSHeader.e_lfanew);

	printf(" ----------------------------------\n\n");

}

void PE64File::PrintFileHeaderInfo() {

	DWORD lOffset = pfDOSHeader.e_lfanew + sizeof(pfNTHeaders.Signature);
	
	printf(" File Header\n");
	printf(" ----------------------------------\n");
	printf(" Member\t\t\t| Offset\t| Size\t| Value\n");
	printf(" ----------------------------------\n");

	printf(" Machine\t\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfNTHeaders.FileHeader.Machine);
	lOffset += sizeof(pfNTHeaders.FileHeader.Machine);

	printf(" NumberOfSections\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfNTHeaders.FileHeader.NumberOfSections);
	lOffset += sizeof(pfNTHeaders.FileHeader.NumberOfSections);

	printf(" TimeDateStamp\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfNTHeaders.FileHeader.TimeDateStamp);
	lOffset += sizeof(pfNTHeaders.FileHeader.TimeDateStamp);

	printf(" PointerToSymbolTable\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfNTHeaders.FileHeader.PointerToSymbolTable);
	lOffset += sizeof(pfNTHeaders.FileHeader.PointerToSymbolTable);

	printf(" NumberOfSymbols\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfNTHeaders.FileHeader.NumberOfSymbols);
	lOffset += sizeof(pfNTHeaders.FileHeader.NumberOfSymbols);

	printf(" SizeOfOptionalHeader\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfNTHeaders.FileHeader.SizeOfOptionalHeader);
	lOffset += sizeof(pfNTHeaders.FileHeader.SizeOfOptionalHeader);

	printf(" Characteristics\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfNTHeaders.FileHeader.Characteristics);
	lOffset += sizeof(pfNTHeaders.FileHeader.Characteristics);

	printf(" ----------------------------------\n\n");

}

void PE64File::PrintDataDirectoriesInfo(DWORD arg_offset) {

	printf(" Data Directories\n");
	printf(" ----------------------------------\n");
	printf(" Member\t\t\t\t| Offset\t| Size\t| Value\n");
	printf(" ----------------------------------\n");

	printf(" Export Directory RVA\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress);
	arg_offset += sizeof(DWORD);

	printf(" Export Directory Size\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[0].Size);
	arg_offset += sizeof(DWORD);

	printf(" Import Directory RVA\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[1].VirtualAddress);
	arg_offset += sizeof(DWORD);

	printf(" Import Directory Size\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[1].Size);
	arg_offset += sizeof(DWORD);

	printf(" Resource Directory RVA\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[2].VirtualAddress);
	arg_offset += sizeof(DWORD);

	printf(" Resource Directory Size\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[2].Size);
	arg_offset += sizeof(DWORD);

	printf(" Exception Directory RVA\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[3].VirtualAddress);
	arg_offset += sizeof(DWORD);

	printf(" Exception Directory Size\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[3].Size);
	arg_offset += sizeof(DWORD);

	printf(" Security Directory RVA\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[4].VirtualAddress);
	arg_offset += sizeof(DWORD);

	printf(" Security Directory Size\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[4].Size);
	arg_offset += sizeof(DWORD);

	printf(" Base Relocation Table RVA\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[5].VirtualAddress);
	arg_offset += sizeof(DWORD);

	printf(" Base Relocation Table Size\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[5].Size);
	arg_offset += sizeof(DWORD);

	printf(" Debug Directory RVA\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[6].VirtualAddress);
	arg_offset += sizeof(DWORD);

	printf(" Debug Directory Size\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[6].Size);
	arg_offset += sizeof(DWORD);

	printf(" Architecture Directory RVA\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[7].VirtualAddress);
	arg_offset += sizeof(DWORD);

	printf(" Architecture Directory Size\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[7].Size);
	arg_offset += sizeof(DWORD);

	printf(" Reserved\t\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[8].VirtualAddress);
	arg_offset += sizeof(DWORD);

	printf(" Reserved\t\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[8].Size);
	arg_offset += sizeof(DWORD);

	printf(" TLS Directory RVA\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[9].VirtualAddress);
	arg_offset += sizeof(DWORD);

	printf(" TLS Directory Size\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[9].Size);
	arg_offset += sizeof(DWORD);

	printf(" Configuration Directory RVA\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[10].VirtualAddress);
	arg_offset += sizeof(DWORD);

	printf(" Configuration Directory Size\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[10].Size);
	arg_offset += sizeof(DWORD);

	printf(" Bound Import Directory RVA\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[11].VirtualAddress);
	arg_offset += sizeof(DWORD);

	printf(" Bound Import Directory Size\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[11].Size);
	arg_offset += sizeof(DWORD);

	printf(" Import Address Table RVA\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[12].VirtualAddress);
	arg_offset += sizeof(DWORD);

	printf(" Import Address Table Size\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[12].Size);
	arg_offset += sizeof(DWORD);

	printf(" Delay Import Directory RVA\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[13].VirtualAddress);
	arg_offset += sizeof(DWORD);

	printf(" Delay Import Directory Size\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[13].Size);
	arg_offset += sizeof(DWORD);

	printf(" .NET Metadata Directory RVA\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[14].VirtualAddress);
	arg_offset += sizeof(DWORD);

	printf(" .NET Metadata Directory Size\t| 0x%08X\t| DWORD\t| 0x%08X\n", arg_offset, pfNTHeaders.OptionalHeader.DataDirectory[14].Size);
	arg_offset += sizeof(DWORD);

	printf(" ----------------------------------\n\n");

}

void PE64File::PrintOptionalHeaderInfo() {

	DWORD lOffset = pfDOSHeader.e_lfanew + sizeof(pfNTHeaders.Signature) + sizeof(pfNTHeaders.FileHeader);
	
	printf(" Optional Header\n");
	printf(" ----------------------------------\n");
	printf(" Member\t\t\t\t| Offset\t| Size\t| Value\n");
	printf(" ----------------------------------\n");

	printf(" Magic\t\t\t\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfNTHeaders.OptionalHeader.Magic);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.Magic);

	printf(" MajorLinkerVersion\t\t| 0x%08X\t| BYTE\t| 0x%02X\n", lOffset, pfNTHeaders.OptionalHeader.MajorLinkerVersion);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.MajorLinkerVersion);

	printf(" MinorLinkerVersion\t\t| 0x%08X\t| BYTE\t| 0x%02X\n", lOffset, pfNTHeaders.OptionalHeader.MinorLinkerVersion);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.MinorLinkerVersion);

	printf(" SizeOfCode\t\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfNTHeaders.OptionalHeader.SizeOfCode);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.SizeOfCode);

	printf(" SizeOfInitializedData\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfNTHeaders.OptionalHeader.SizeOfInitializedData);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.SizeOfInitializedData);

	printf(" SizeOfUninitializedData\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfNTHeaders.OptionalHeader.SizeOfUninitializedData);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.SizeOfUninitializedData);

	printf(" AddressOfEntryPoint\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfNTHeaders.OptionalHeader.AddressOfEntryPoint);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.AddressOfEntryPoint);

	printf(" BaseOfCode\t\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfNTHeaders.OptionalHeader.BaseOfCode);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.BaseOfCode);

	printf(" ImageBase\t\t\t| 0x%08X\t| QWORD\t| 0x%016X\n", lOffset, pfNTHeaders.OptionalHeader.ImageBase);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.ImageBase);

	printf(" SectionAlignment\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfNTHeaders.OptionalHeader.SectionAlignment);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.SectionAlignment);

	printf(" FileAlignment\t\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfNTHeaders.OptionalHeader.FileAlignment);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.FileAlignment);

	printf(" MajorOperatingSystemVersion\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfNTHeaders.OptionalHeader.MajorOperatingSystemVersion);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.MajorOperatingSystemVersion);

	printf(" MinorOperatingSystemVersion\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfNTHeaders.OptionalHeader.MinorOperatingSystemVersion);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.MinorOperatingSystemVersion);

	printf(" MajorImageVersion\t\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfNTHeaders.OptionalHeader.MajorImageVersion);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.MajorImageVersion);

	printf(" MinorImageVersion\t\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfNTHeaders.OptionalHeader.MinorImageVersion);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.MinorImageVersion);

	printf(" MajorSubsystemVersion\t\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfNTHeaders.OptionalHeader.MajorSubsystemVersion);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.MajorSubsystemVersion);

	printf(" MinorSubsystemVersion\t\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfNTHeaders.OptionalHeader.MinorSubsystemVersion);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.MinorSubsystemVersion);

	printf(" Win32VersionValue\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfNTHeaders.OptionalHeader.Win32VersionValue);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.Win32VersionValue);

	printf(" SizeOfImage\t\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfNTHeaders.OptionalHeader.SizeOfImage);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.SizeOfImage);

	printf(" SizeOfHeaders\t\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfNTHeaders.OptionalHeader.SizeOfHeaders);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.SizeOfHeaders);

	printf(" CheckSum\t\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfNTHeaders.OptionalHeader.CheckSum);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.CheckSum);

	printf(" Subsystem\t\t\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfNTHeaders.OptionalHeader.Subsystem);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.Subsystem);

	printf(" DllCharacteristics\t\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfNTHeaders.OptionalHeader.DllCharacteristics);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.DllCharacteristics);

	printf(" SizeOfStackReserve\t\t| 0x%08X\t| QWORD\t| 0x%016X\n", lOffset, pfNTHeaders.OptionalHeader.SizeOfStackReserve);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.SizeOfStackReserve);

	printf(" SizeOfStackCommit\t\t| 0x%08X\t| QWORD\t| 0x%016X\n", lOffset, pfNTHeaders.OptionalHeader.SizeOfStackCommit);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.SizeOfStackCommit);

	printf(" SizeOfHeapReserve\t\t| 0x%08X\t| QWORD\t| 0x%016X\n", lOffset, pfNTHeaders.OptionalHeader.SizeOfHeapReserve);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.SizeOfHeapReserve);

	printf(" SizeOfHeapCommit\t\t| 0x%08X\t| QWORD\t| 0x%016X\n", lOffset, pfNTHeaders.OptionalHeader.SizeOfHeapCommit);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.SizeOfHeapCommit);

	printf(" LoaderFlags\t\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfNTHeaders.OptionalHeader.LoaderFlags);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.LoaderFlags);

	printf(" NumberOfRvaAndSizes\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfNTHeaders.OptionalHeader.NumberOfRvaAndSizes);
	lOffset += sizeof(pfNTHeaders.OptionalHeader.NumberOfRvaAndSizes);

	printf(" ----------------------------------\n\n");

	PrintDataDirectoriesInfo(lOffset);

}

void PE64File::PrintNTHeadersInfo() {

	printf(" NT Headers\n");
	printf(" ----------------------------------\n");
	printf(" Member\t\t| Offset\t| Size\t| Value\n");
	printf(" ----------------------------------\n");

	printf(" Signature\t| 0x%08X\t| DWORD\t| 0x%08X\n", pfDOSHeader.e_lfanew, pfNTHeaders.Signature);

	printf(" ----------------------------------\n\n");

	PrintFileHeaderInfo();
	PrintOptionalHeaderInfo();

}

void PE64File::PrintSectionHeadersInfo() {

	printf(" Section Headers\n");
	printf(" ----------------------------------\n");
	printf(" Name\t\t| Virtual Size\t| Virtual Address\t| Raw Size\t| Raw Address\t\t| Reloc Address\t| Linenumbers\t\t| Relocations Number\t| Linenumbers Number\t| Characteristics\n");
	printf(" ----------------------------------\n");

	for (int i = 0; i < pfNTHeaders.FileHeader.NumberOfSections; i++)
	{
		printf(" %.8s\t\t| 0x%08X\t| 0x%08X\t| 0x%08X\t| 0x%08X\t\t| 0x%08X\t| 0x%08X\t\t| 0x%04X\t\t| 0x%04X\t\t| 0x%08X\n",
			pfSectionHeaders[i].Name,
			pfSectionHeaders[i].Misc.VirtualSize,
			pfSectionHeaders[i].VirtualAddress,
			pfSectionHeaders[i].SizeOfRawData,
			pfSectionHeaders[i].PointerToRawData,
			pfSectionHeaders[i].PointerToRelocations,
			pfSectionHeaders[i].PointerToLinenumbers,
			pfSectionHeaders[i].NumberOfRelocations,
			pfSectionHeaders[i].NumberOfLinenumbers,
			pfSectionHeaders[i].Characteristics);
	}

	printf(" ----------------------------------\n\n");

}

void PE64File::PrintExportTableInfo() {

	DWORD lOffset = GetOffset(pfExportDirectory.VirtualAddress);
	
	printf(" Export Table\n");
	printf(" ----------------------------------\n");
	printf(" Member\t\t\t| Offset\t| Size\t| Value\n");
	printf(" ----------------------------------\n");

	printf(" Characteristics\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfExportTable.Characteristics);
	lOffset += sizeof(DWORD);

	printf(" TimeDateStamp\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfExportTable.TimeDateStamp);
	lOffset += sizeof(DWORD);

	printf(" MajorVersion\t\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfExportTable.MajorVersion);
	lOffset += sizeof(WORD);

	printf(" MinorVersion\t\t| 0x%08X\t| WORD\t| 0x%04X\n", lOffset, pfExportTable.MinorVersion);
	lOffset += sizeof(WORD);

	printf(" Name \t\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfExportTable.Name);
	lOffset += sizeof(DWORD);

	printf(" Base\t\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfExportTable.Base);
	lOffset += sizeof(DWORD);

	printf(" NumberOfFunctions\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfExportTable.NumberOfFunctions);
	lOffset += sizeof(DWORD);

	printf(" NumberOfNames\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfExportTable.NumberOfNames);
	lOffset += sizeof(DWORD);

	printf(" AddressOfFunctions\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfExportTable.AddressOfFunctions);
	lOffset += sizeof(DWORD);

	printf(" AddressOfNames\t\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfExportTable.AddressOfNames);
	lOffset += sizeof(DWORD);

	printf(" AddressOfNameOrdinals\t| 0x%08X\t| DWORD\t| 0x%08X\n", lOffset, pfExportTable.AddressOfNameOrdinals);
	lOffset += sizeof(DWORD);

	printf(" ----------------------------------\n");

	printf(" Exported Functions\n");
	printf(" ----------------------------------\n");
	printf(" Ordinal\t| Function RVA\t| Name Ordinal\t| Name RVA\t| Name\n");
	printf(" ----------------------------------\n");

	for (int i = 0; i < pfExportTable.NumberOfNames; i++)
	{
		DWORD lNameRVA = pfExportNamePointerTable[i];
		WORD lNameOrdinal = pfExportOrdinalTable[i];
		DWORD lFunctionRVA = pfExportAddressTable[lNameOrdinal];

		printf(" 0x%04X\t\t| 0x%08X\t| 0x%04X\t| 0x%08X\t| %s\n",
			lNameOrdinal + pfExportTable.Base, lFunctionRVA, lNameOrdinal, lNameRVA, GetName(lNameRVA));
	}

	printf(" ----------------------------------\n\n");

}

void PE64File::PrintImportTableInfo() {

	printf(" Import Table\n");
	printf(" ----------------------------------\n");
	printf(" Module Name\t\t| Imports\t| OFTs\t\t| TimeDateStamp\t| ForwarderChain\t| Name RVA\t| FTs (IAT)\n");
	printf(" ----------------------------------\n");

	for (int i = 0; i < pfImportDirectoryCount; i++)
	{
		DWORD lOffset = GetOffset(pfImportTable[i].DUMMYUNIONNAME.OriginalFirstThunk);
		int lImportCount = 0;

		while (true)
		{
			QWORD lTemp;

			fseek(pfPEFile, lOffset, SEEK_SET);
			fread(&lTemp, sizeof(QWORD), 1, pfPEFile);

			if (lTemp == 0x0)
			{
				break;
			}

			lOffset += sizeof(QWORD);
			lImportCount++;
		}

		printf(" %s\t| %d\t\t| 0x%08X\t| 0x%08X\t| 0x%08X\t\t| 0x%08X\t| 0x%08X\n",
			GetName(pfImportTable[i].Name),
			lImportCount,
			pfImportTable[i].DUMMYUNIONNAME.OriginalFirstThunk,
			pfImportTable[i].TimeDateStamp,
			pfImportTable[i].ForwarderChain,
			pfImportTable[i].Name,
			pfImportTable[i].FirstThunk);
		printf(" ----------------------------------\n");

		printf("\t----------------------------------\n");
		printf("\tOFTs\t\t\t| FTs (IAT)\t\t| Hint\t\t| Name\n");
		printf("\t----------------------------------\n");

		DWORD lILTOffset = GetOffset(pfImportTable[i].DUMMYUNIONNAME.OriginalFirstThunk);
		DWORD lIATOffset = GetOffset(pfImportTable[i].FirstThunk);

		for (int j = 0; j < lImportCount; j++)
		{
			QWORD lILTEntry, lIATEntry;

			fseek(pfPEFile, (lILTOffset + (j * sizeof(QWORD))), SEEK_SET);
			fread(&lILTEntry, sizeof(QWORD), 1, pfPEFile);

			fseek(pfPEFile, (lIATOffset + (j * sizeof(QWORD))), SEEK_SET);
			fread(&lIATEntry, sizeof(QWORD), 1, pfPEFile);

			QWORD lFlag = lILTEntry & 0x8000000000000000;
			DWORD lHintRVA = 0x0;
			WORD lOrdinal = 0x0;

			if (lFlag == 0x0)
			{
				lHintRVA = lILTEntry;
			}
			else if (lFlag == 0x8000000000000000)
			{
				lOrdinal = lILTEntry;
			}

			if (lFlag == 0x0)
			{
				IMAGE_IMPORT_BY_NAME lHint;

				fseek(pfPEFile, GetOffset(lHintRVA), SEEK_SET);
				fread(&lHint, sizeof(IMAGE_IMPORT_BY_NAME), 1, pfPEFile);

				printf("\t0x%016X\t| 0x%016X\t| 0x%04X\t| %s\n", lILTEntry, lIATEntry, lHint.Hint, lHint.Name);
			}
			else if (lFlag == 0x8000000000000000)
			{
				printf("\t0x%016X\t| 0x%016X\t| N/A\t\t| Ordinal: 0x%08X\n", lILTEntry, lIATEntry, lOrdinal);
			}
		}

		printf("\n ----------------------------------\n");
	}

}

void PE64File::PrintInfo() {

	printf("\n\n");

	PrintFileInfo();
	PrintDOSHeaderInfo();
	PrintNTHeadersInfo();
	PrintSectionHeadersInfo();
	
	if (pfExportDirectory.Size != 0)
	{
		PrintExportTableInfo();
	}

	if (pfImportDirectory.Size != 0)
	{
		PrintImportTableInfo();
	}

}
