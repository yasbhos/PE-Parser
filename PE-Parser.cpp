#include <iostream>
#include <fstream>
#include "PEFile.h"

int main(int argc, char* argv[])
{
	if (argc != 2) {
		printf("Usage: %s [path to executable]\n", argv[0]);
		return 1;
	}

	FILE* lPEFile;
	fopen_s(&lPEFile, argv[1], "rb");

	if (lPEFile == NULL) {
		printf("Can't open file.\n");
		return 1;
	}

	if (InitParse(lPEFile) == 1) {
		exit(1);
	}
	else if (InitParse(lPEFile) == 32) {
		PE32File OPEFile(argv[1], lPEFile);
		OPEFile.PrintInfo();
		fclose(lPEFile);
		exit(0);
	}
	else if (InitParse(lPEFile) == 64) {
		PE64File OPEFile(argv[1], lPEFile);
		OPEFile.PrintInfo();
		fclose(lPEFile);
		exit(0);
	}

	return 0;
}
