#include "PEFile.h"


int InitParse(FILE* arg_pefile) {

	IMAGE_DOS_HEADER lDOSHeader;
	WORD lPEFileType;

	fseek(arg_pefile, 0, SEEK_SET);
	fread(&lDOSHeader, sizeof(IMAGE_DOS_HEADER), 1, arg_pefile);

	if (lDOSHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Error. Not a PE file.\n");
		return 1;
	}

	fseek(arg_pefile, (lDOSHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)), SEEK_SET);
	fread(&lPEFileType, sizeof(WORD), 1, arg_pefile);

	if (lPEFileType == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		return 32;
	}
	else if (lPEFileType == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return 64;
	}
	else {
		printf("Error while parsing IMAGE_OPTIONAL_HEADER.Magic.\n");
		return 1;
	}

}
