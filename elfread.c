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

 /*
  *  NOTES:
  *  #include <elf.h> just reading the source
  *  the best way to learn is to read the fuckin structs make a program that reads in an elf
  *  start off by reading in an Elf_Ehdr gotta know what kind of elf file it is before actually
  *  trying to interpret the data past the magic ehdr->e_ident[EI_CLASS] can be either ELFCLASS64 or ELFCLASS32
  *  depending on this everything thereon will be an Elf32_blah or an Elf64_blah
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
int
read_file_into_mem(const char* filename, void** data_out, size_t* size_out);
int
write_mem_to_file(const char* filename, const void* data, size_t size);

int
main(int argc, char** argv)
{
        uint8_t* data;
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

        read_file_into_mem("/bin/ls", (void**)&data, &datasz);
        memcpy(&ehdr, data, sizeof(Elf64_Ehdr));
        if (strncmp(ELFMAG, &ehdr.e_ident[EI_MAG0], SELFMAG) != 0)
                err_exit("* Not an ELFMAG");

        status = true;
        ehdr.e_type = ehdr.e_ident[EI_CLASS];
        if (ehdr.e_type < ELFCLASS32 || ehdr.e_type > ELFCLASS64) {
                status = false;
                ehdr.e_type = ELFCLASSNONE;
        }

        ehdr.e_machine = ehdr.e_ident[EI_DATA];
        if (ehdr.e_machine < ELFDATA2LSB || ehdr.e_machine > ELFDATA2MSB) {
                status = false;
                ehdr.e_machine = ELFDATANONE;
        }

        ehdr.e_version = ehdr.e_ident[EI_VERSION];
        if (ehdr.e_version != EV_CURRENT) {
                status = false;
                ehdr.e_version = EV_NONE;
        }

        if (ehdr.e_ident[EI_OSABI] >= ELFOSABI_SOLARIS && ehdr.e_ident[EI_OSABI] <= ELFOSABI_OPENBSD)
                ehdr.e_ident[EI_OSABI] -= 2;
        else if (ehdr.e_ident[EI_OSABI] >= ELFOSABI_ARM_AEABI)
                ehdr.e_ident[EI_OSABI] = (sizeof(elf_osabi) / sizeof(elf_osabi[0])) - 1;

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
                "  Type:                                \n"
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
                elf_class[ehdr.e_type],
                elf_data[ehdr.e_machine],
                ehdr.e_version, elf_version[ehdr.e_version],
                elf_osabi[ehdr.e_ident[EI_OSABI]],
                ehdr.e_ident[EI_ABIVERSION]
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
