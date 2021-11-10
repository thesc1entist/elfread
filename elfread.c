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
        unsigned char elf_ei_osabi, elf_ei_data, elf_ei_class;
        int magic_flag;
        size_t datasz;
        Elf64_Ehdr ehdr;
        Elf64_Half elf_e_type;
        Elf64_Word elf_e_version;

        const char* elf_class_id[ELFCLASSNUM] = {
                #include "./include/e_class_strings.h" 
        };
        const char* elf_data_id[ELFDATANUM] = {
                #include "./include/e_data_strings.h" 
        };
        const char* elf_osabi_id[] = {
                #include "./include/e_osabi_strings.h" 
        };
        const char* elf_e_type_id[] = {
                #include "./include/e_type_strings.h" 
        };
        const char* elf_e_machine_id[EM_NUM] = {
                #include "./include/e_machine_strings.h" 
        };
        const char* elf_e_version_id[EV_NUM] = {
                #include "./include/e_version_strings.h" 
        };

        read_file_into_mem("/bin/ls", (void**)&data, &datasz);
        memcpy(&ehdr, data, sizeof(Elf64_Ehdr));
        if (strncmp(ELFMAG, &ehdr.e_ident[EI_MAG0], SELFMAG) != 0)
                err_exit("* Not an ELFMAG");

        elf_ei_class = ehdr.e_ident[EI_CLASS];
        if (elf_ei_class < ELFCLASS32 || elf_ei_class > ELFCLASS64)
                elf_ei_class = ELFCLASSNONE;

        elf_ei_data = ehdr.e_ident[EI_DATA];
        if (elf_ei_data < ELFDATA2LSB || elf_ei_data > ELFDATA2MSB)
                elf_ei_data = ELFDATANONE;

        elf_ei_osabi = ehdr.e_ident[EI_OSABI];
        if (elf_ei_osabi >= ELFOSABI_SOLARIS && elf_ei_osabi <= ELFOSABI_OPENBSD)
                elf_ei_osabi -= 2;
        else if (elf_ei_osabi >= ELFOSABI_ARM_AEABI)
                elf_ei_osabi = (sizeof(elf_osabi_id) / sizeof(elf_osabi_id[0])) - 1;

        elf_e_type = ehdr.e_type;
        if (elf_e_type > 5 && elf_e_type < ET_LOOS)
                elf_e_type = ET_NONE;
        else if (elf_e_type >= ET_LOOS && elf_e_type <= ET_HIOS)
                elf_e_type = INDEX_ET_OS;
        else if (elf_e_type >= ET_HIOS && elf_e_type <= ET_LOPROC)
                elf_e_type = INDEX_ET_PROC;

        elf_e_version = ehdr.e_version != EV_CURRENT ? EV_NONE : ehdr.e_version;

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
                "  Version:                             %d\n"
                "  OS/ABI:                              %s\n"
                "  ABI Version:                         %d\n"
                "  Type:                                %s\n"
                "  Machine:                             %s\n"
                "  Version:                             0x%x (%s)\n"
                "  Entry point address:                 0x%x\n"
                "  Start of program headers:            %d (bytes into file)\n"
                "  Start of section headers:            %d (bytes into file)\n"
                "  Flags:                               0x%x\n"
                "  Size of this header:                 %d (bytes)\n"
                "  Size of program headers:             %d (bytes)\n"
                "  Number of program headers:           %d\n"
                "  Size of section headers:             %d (bytes)\n"
                "  Number of section headers:           %d\n"
                "  Section header string table index:   %d\n",
                elf_class_id[elf_ei_class],
                elf_data_id[elf_ei_data],
                (int)ehdr.e_ident[EI_VERSION],
                elf_osabi_id[elf_ei_osabi],
                (int)ehdr.e_ident[EI_ABIVERSION], // Further specifies the ABI version.
                                             // Its interpretation depends on the target ABI.
                                             // Linux kernel (after at least 2.6) has no definition of it,
                                             // so it is ignored for statically-linked executables.
                                             // In that case, offset and size of EI_PAD are 8.
                elf_e_type_id[elf_e_type],
                ehdr.e_machine >= EM_NUM ? "special\n" : elf_e_machine_id[ehdr.e_machine],
                ehdr.e_version, elf_e_version_id[elf_e_version],
                ehdr.e_entry,
                ehdr.e_phoff,
                ehdr.e_shoff,
                ehdr.e_flags,
                ehdr.e_ehsize,
                ehdr.e_phentsize,
                ehdr.e_phnum,
                ehdr.e_shentsize,
                ehdr.e_shnum,
                ehdr.e_shstrndx
        );

        free(data);

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
