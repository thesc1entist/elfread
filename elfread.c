/* elfread.c
 * the-scientist@rootstorm.com
 * spl0its-r-us security
 *
 * 100% of the proceeds that wind up in these accounts will be donated to animal shelters.
 * ================================================================================================================
 * BITCOIN: bc1qc0x6qdsk7auhsrym6vz0rtafnl2qgqjk7yy3tn
 * ETHEREUM: 0x482d85E39Ce865Dcf7c26bFDD6e52AB203d0f555
 * DOGECOIN: DPYxWnnyYzmPYWP92iqo4DizJht3rZnYnu
 * LITECOIN: ltc1qea6ehaanwr9q3jygmw75q35avk8t74h7sc5uc3
 * ETHCLASSIC: 0x6C63D4428Cb6BfDB7AC72b447A8B29D811395052
 * CARDANO: addr1qxn4przua2crcrgwt3pk5465ym3syytfn2v7gssu7ayuvpvefqwdvkgzn4y3j5d5ynsh03kae9k8d0z8yuh8excuv6xqdl4kyt
 * ================================================================================================================
 *
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <elf.h>
#include <string.h> // memset
#include <stdbool.h>

#define         err_exit(msg) do { perror(msg); \
                        exit(EXIT_FAILURE); \
                        } while (0);

#define         INDEX_ET_OS 6	
#define         INDEX_ET_PROC 7

int
read_file_into_mem(const char* filename, void** data_out, size_t* size_out);
int
write_mem_to_file(const char* filename, const void* data, size_t size);

int
main(int argc, char** argv)
{
        uint8_t* data;
        const char* e_typeptr;
        int magic_flag;
        size_t datasz;
        Elf64_Ehdr ehdr;
        Elf64_Half e_type;
        bool status;

        const char* elf_class[ELFCLASSNUM] = {
                "NONE",
                "ELF32",
                "ELF64"
        };

        const char* elf_data[ELFDATANUM] = {
                "Invalid data encoding",
                "2's complement, little endian",
                "2's complement, big endian"
        };

        const char* elf_version[EV_NUM] = {
                "Invalid ELF version",
                "Current version"
        };

        const char* elf_osabi[] = {
                "UNIX System V ABI",
                "HP-UX",
                "NetBSD.",
                "Object uses GNU ELF extensions",
                "Sun Solaris",
                "IBM AIX",
                "SGI Irix",
                "FreeBSD",
                "Compaq TRU64 UNIX",
                "Novell Modesto",
                "OpenBSD",
                "Standalone (embedded) application"
        };

        const char* elf_e_type[] = {
                "NONE No file type",
                "REL Relocatable file",
                "EXEC Executable file",
                "DYN Shared object file",
                "CORE Core file",
                "NUM Number of defined types",
                "OS-specific range",
                "Processor-specific range"
        };

        read_file_into_mem("/bin/ls", (void**)&data, &datasz);
        memcpy(&ehdr, data, sizeof(Elf64_Ehdr));
        if (strncmp(ELFMAG, &ehdr.e_ident[EI_MAG0], SELFMAG) != 0)
                err_exit("* Not an ELFMAG");

        status = true;
        ehdr.e_ident[EI_CLASS] = -1; 
        if (ehdr.e_ident[EI_CLASS] < ELFCLASS32 || ehdr.e_ident[EI_CLASS] > ELFCLASS64) {
                status = false;
                ehdr.e_ident[EI_CLASS] = ELFCLASSNONE;
        }

        if (ehdr.e_ident[EI_DATA] < ELFDATA2LSB || ehdr.e_ident[EI_DATA] > ELFDATA2MSB) {
                status = false;
                ehdr.e_ident[EI_DATA] = ELFDATANONE;
        }

        if (ehdr.e_ident[EI_VERSION] != EV_CURRENT) {
                status = false;
                ehdr.e_ident[EI_VERSION] = EV_NONE;
        }

        if (ehdr.e_ident[EI_OSABI] >= ELFOSABI_SOLARIS && ehdr.e_ident[EI_OSABI] <= ELFOSABI_OPENBSD)
                ehdr.e_ident[EI_OSABI] -= 2;
        else if (ehdr.e_ident[EI_OSABI] >= ELFOSABI_ARM_AEABI)
                ehdr.e_ident[EI_OSABI] = (sizeof(elf_osabi) / sizeof(elf_osabi[0])) - 1;

        e_type = ehdr.e_type;
        if (e_type > 5 && e_type < ET_LOOS)
                e_type = ET_NONE;
        else if (e_type >= ET_LOOS && e_type <= ET_HIOS)
                e_type = INDEX_ET_OS;
        else if (e_type >= ET_HIOS && e_type <= ET_LOPROC)
                e_type = INDEX_ET_PROC;

        printf(
                "ELF Header:\n"
                "  Magic:   "
        );
        for (int i = 0; i < EI_NIDENT; i++)
                printf("%.2x ", ehdr.e_ident[i]);
        putchar('\n');
        printf(
                "  Class:                               %s\n"
                "  Data:                                %s\n"
                "  Version:                             %d(%s)\n"
                "  OS/ABI:                              %s\n"
                "  ABI Version:                         %d\n"
                "  Type:                                %s\n"
                "  Machine:                             \n"
                "  Version:                             \n"
                "  Entry point address:                 \n"
                "  Start of program headers:            \n"
                "  Start of section headers:            \n"
                "  Flags:                               \n"
                "  Size of this header:                 \n"
                "  Size of program headers:             \n"
                "  Number of program headers:           \n"
                "  Size of section headers:             \n"
                "  Number of section headers:           \n"
                "  Section header string table index:   \n",
                elf_class[ehdr.e_ident[EI_CLASS]],
                elf_data[ehdr.e_ident[EI_DATA]],
                ehdr.e_version, elf_version[ehdr.e_ident[EI_VERSION]],
                elf_osabi[ehdr.e_ident[EI_OSABI]],
                ehdr.e_ident[EI_ABIVERSION], // Further specifies the ABI version.
                                             // Its interpretation depends on the target ABI.
                                             // Linux kernel (after at least 2.6) has no definition of it,
                                             // so it is ignored for statically-linked executables.
                                             // In that case, offset and size of EI_PAD are 8.
                elf_e_type[e_type]
        );

        free(data);
        if (status == false)
                err_exit("* bad ELF");

        return 0;
}


int
read_file_into_mem(const char* filename, void** data_out, size_t* size_out)
{
        FILE* file = fopen(filename, "rb");
        if (file == NULL)
                return 0;

        fseek(file, 0, SEEK_END);
        long filesize = ftell(file);
        rewind(file);

        void* mem = malloc(filesize);
        if (mem == NULL) {
                fclose(file);
                return 0;
        }

        if (fread(mem, filesize, 1, file) != 1) {
                printf("Failed to read data\n");
                fclose(file);
                free(mem);
                return 0;
        }

        fclose(file);

        *data_out = mem;
        *size_out = filesize;
        return 1;
}


int
write_mem_to_file(const char* filename, const void* data, size_t size)
{
        struct stat sb;
        int fd;
        int success = 0;

        FILE* output_file = fopen(filename, "wb");
        if (output_file == NULL) {
                printf("Failed to open %s for writing\n", filename);
                return 0;
        }

        if (fwrite(data, size, 1, output_file) != 1) {
                printf("Failed to write data\n");
                goto err;
        }

        fd = fileno(output_file);

        if (fstat(fd, &sb)) {
                printf("Failed to stat %s\n", filename);
                goto err;
        }

        if (fchmod(fd, sb.st_mode | S_IXUSR | S_IXGRP | S_IXOTH)) {
                printf("Failed to fchmod %s\n", filename);
                goto err;
        }

        success = 1;

err:
        fclose(output_file);
        return success;
}
