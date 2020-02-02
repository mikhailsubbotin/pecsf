// ========================================= //
//             PE CheckSum Fixer             //
// ----------------------------------------- //
//  Author: Mikhail Subbotin                 //
//  E-Mail: subbotin.mikhail.work@gmail.com  //
// ----------------------------------------- //
//      Licensed under the MIT License.      //
// ========================================= //

#include <stdio.h>
#include <windows.h>
#include <imagehlp.h>

int main(int argc, char **argv)
{
    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID FileMapView;
    DWORD dwFileSize;
    DWORD dwHeaderSum;
    DWORD dwCheckSum;
    PIMAGE_NT_HEADERS pNTHeaders;
    DWORD dwErrorCode;

    if (argc == 2)
    {
        printf("%s: ", argv[1]);

        hFile = CreateFile(argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFile != INVALID_HANDLE_VALUE)
        {
            if (hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL))
            {
                if (FileMapView = MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0))
                {
                    dwFileSize = GetFileSize(hFile, NULL);

                    if (dwFileSize != INVALID_FILE_SIZE)
                    {
                        if (pNTHeaders = CheckSumMappedFile(FileMapView, dwFileSize, &dwHeaderSum, &dwCheckSum))
                        {
                            if (dwHeaderSum != dwCheckSum)
                            {
                                pNTHeaders->OptionalHeader.CheckSum = dwCheckSum;

                                printf("PE checksum value has been updated! 0x%.8X -> 0x%.8X\n", dwHeaderSum, dwCheckSum);
                            }
                            else
                            {
                                printf("PE checksum correction are not required!\n");
                            }
                        }
                        else
                        {
                            dwErrorCode = GetLastError();

                            if (!dwErrorCode)
                            {
                                printf("Invalid file format!\n");
                            }
                            else
                            {
                                printf("System error! Code: %d\n", dwErrorCode);
                            }
                        }
                    }
                    else
                    {
                        printf("System error! Code: %d\n", GetLastError());
                    }
                    UnmapViewOfFile(FileMapView);
                }
                else
                {
                    printf("System error! Code: %d\n", GetLastError());
                }
                CloseHandle(hFileMapping);
            }
            else
            {
                printf("System error! Code: %d\n", GetLastError());
            }
            CloseHandle(hFile);
        }
        else
        {
            dwErrorCode = GetLastError();

            if ((dwErrorCode == ERROR_FILE_NOT_FOUND) || (dwErrorCode == ERROR_PATH_NOT_FOUND))
            {
                printf("File not found!\n");
            }
            else if (dwErrorCode == ERROR_SHARING_VIOLATION)
            {
                printf("Access denied!\n");
            }
            else
            {
                printf("System error! Code: %d\n", dwErrorCode);
            }
        }
    }
    else
    {
        printf("PE CheckSum Fixer\n"\
               "-----------------\n"\
               "Usage: pecsf <target_executable>\n");
    }
    return 0;
}
