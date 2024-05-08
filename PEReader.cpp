
#include <iostream>
#include <windows.h>

int main(int argv, char** argc)
{

    if (2 != argv)
    {
        std::cout << "Use: PERedaer path_del_dll" << std::endl;
        return 1;
    }


    const char* dllPath = argc[1];

    HMODULE hModule = ::LoadLibraryA(dllPath);
    if (NULL == hModule)
    {
        std::cout << "Error: No se pudo cargar el DLL Err:" <<  GetLastError() << std::endl;
        return 1;
    }

    DWORD baseAddress = reinterpret_cast<DWORD>(hModule);
    IMAGE_DOS_HEADER* pDosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(baseAddress);
   
    if (!pDosHdr || (IMAGE_DOS_SIGNATURE != pDosHdr->e_magic))
    {
        std::cout << "Error: Formato de archivo no valido." << std::endl;
    }
    else
    {
        IMAGE_NT_HEADERS* pNtHdrs = reinterpret_cast<IMAGE_NT_HEADERS*>(baseAddress + pDosHdr->e_lfanew);
        if (IMAGE_NT_SIGNATURE != pNtHdrs->Signature)
        {
            std::cout << "Error: Formato de archivo PE no valido." << std::endl;
        }
        else
        {
            IMAGE_DATA_DIRECTORY exportDirectory = pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (0 == exportDirectory.VirtualAddress || 0 == exportDirectory.Size)
            {
                std::cout << "No hay tabla de exportaciones en este DLL." << std::endl;
            }
            else
            {
                IMAGE_EXPORT_DIRECTORY* exportDirectoryPtr = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(baseAddress + exportDirectory.VirtualAddress);

                DWORD* functionNames = reinterpret_cast<DWORD*>(baseAddress + exportDirectoryPtr->AddressOfNames);
                DWORD numFunctions = exportDirectoryPtr->NumberOfNames;

                std::cout << "Funciones Exportadas:" << std::endl;

                for (DWORD i = 0; i < numFunctions; i++)
                    std::cout << "* " << reinterpret_cast<const char*>(functionNames[i] + baseAddress) << std::endl;
            }
        }
    }
    
    FreeLibrary(hModule);
    return std::cin.get();
}