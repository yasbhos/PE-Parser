#pragma once
#include "winnt.h"
#include <string>

class PE32File
{
public:
    PE32File(char* arg_name, FILE* arg_pefile);

    void PrintInfo();

private:
    char* pfName;
    FILE* pfPEFile;

    IMAGE_DOS_HEADER     pfDOSHeader;
    IMAGE_NT_HEADERS32   pfNTHeaders;

    IMAGE_DATA_DIRECTORY pfExportDirectory;
    IMAGE_DATA_DIRECTORY pfImportDirectory;
    IMAGE_DATA_DIRECTORY pfResourceDirectory;
    IMAGE_DATA_DIRECTORY pfExceptionDirectory;
    IMAGE_DATA_DIRECTORY pfSecurityDirectory;
    IMAGE_DATA_DIRECTORY pfBaseRelocDirectory;
    IMAGE_DATA_DIRECTORY pfDebugDirectory;
    IMAGE_DATA_DIRECTORY pfArchitectureDirectory;
    IMAGE_DATA_DIRECTORY pfGlobalPTRDirectory;
    IMAGE_DATA_DIRECTORY pfTLSDirectory;
    IMAGE_DATA_DIRECTORY pfLoadConfigDirectory;
    IMAGE_DATA_DIRECTORY pfBoundImportDirectory;
    IMAGE_DATA_DIRECTORY pfIATDirectory;
    IMAGE_DATA_DIRECTORY pfDelayImportDirectory;
    IMAGE_DATA_DIRECTORY pfComDescriptorDirectory;

    PIMAGE_SECTION_HEADER pfSectionHeaders;

    IMAGE_EXPORT_DIRECTORY pfExportTable;
    DWORD* pfExportAddressTable;
    DWORD* pfExportNamePointerTable;
    WORD*  pfExportOrdinalTable;

    PIMAGE_IMPORT_DESCRIPTOR pfImportTable;
    int pfImportDirectoryCount;

    DWORD GetOffset(DWORD arg_va);
    char* GetName(DWORD arg_va);

    void ParseFile();
    void ParseDOSHeader();
    void ParseNTHeaders();
    void ParseSectionHeaders();
    void ParseExportDirectory();
    void ParseImportDirectory();

    void PrintFileInfo();
    void PrintDOSHeaderInfo();
    void PrintFileHeaderInfo();
    void PrintOptionalHeaderInfo();
    void PrintDataDirectoriesInfo(DWORD arg_offset);
    void PrintNTHeadersInfo();
    void PrintSectionHeadersInfo();
    void PrintExportTableInfo();
    void PrintImportTableInfo();
};
