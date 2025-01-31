#pragma once
#include <cstdint>
#include <memory>

enum _MEMORY_INFORMATION_CLASS;
typedef _MEMORY_INFORMATION_CLASS MEMORY_INFORMATION_CLASS;

namespace vacmon {
    class logger;

    namespace steam {
        class mapped_module_info;
        class module_info;
    }

    class hooks {
    public:
        static hooks& get();

        bool install();
        bool uninstall();

    protected:
        static bool __stdcall load_image(
            steam::module_info* info,
            std::uint8_t flags
        );

        static int __cdecl protect_image(
            steam::mapped_module_info* info
        );

        static NTSTATUS NTAPI nt_query_virtual_memory(
            HANDLE process_handle,
            PVOID base_address,
            MEMORY_INFORMATION_CLASS memory_information_class,
            PVOID memory_information,
            SIZE_T memory_information_length,
            PSIZE_T return_length
        );

    protected:
        decltype(&load_image) m_load_image;
        decltype(&protect_image) m_protect_image;
        decltype(&nt_query_virtual_memory) m_nt_query_virtual_memory;

        std::unique_ptr<logger> m_logger;
    };
}

enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation,
    MemoryWorkingSetInformation,
    MemoryMappedFilenameInformation,
    MemoryRegionInformation,
    MemoryWorkingSetExInformation,
    MemorySharedCommitInformation,
    MemoryImageInformation,
    MemoryRegionInformationEx,
    MemoryPrivilegedBasicInformation,
    MemoryEnclaveImageInformation,
    MemoryBasicInformationCapped,
    MemoryPhysicalContiguityInformation,
    MemoryBadInformation,
    MemoryBadInformationAllProcesses,
    MemoryImageExtensionInformation,
    MaxMemoryInfoClass
};
