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
#include <stdio.h>      /* for printf */
#include <stdlib.h>     /* for exit */
#include <inttypes.h>   /* for uint8 */ 
#include <string.h>     /* memset */ 
#include <errno.h> 

#include <getopt.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdbool.h>

#define         err_exit(msg) do { perror(msg); \
                        exit(EXIT_FAILURE); \
                        } while (0);

#define         INDEX_ET_OS 6	
#define         INDEX_ET_PROC 7

#define         ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

int
read_file_into_mem(const char* filename, void** data_out, size_t* size_out);
int
write_mem_to_file(const char* filename, const void* data, size_t size);
void
display_elf_header(const Elf64_Ehdr* ehdr);

const char* g_help_menu = {
        "Usage: elfread <option(s)> elf-file(s)\n"
        " Display information about the contents of ELF format files\n"
        " Options are:\n"
        "\n"
        "-h --file-header               Display the ELF file header\n"
        "-l --program-headers           Display the program headers\n"
        "   --segments                  An alias for --program - headers\n"
        "-H --help                      Display this information\n\n"
        "                               the-scientist@rootstorm.com\n"
        "                               spl0its-r-us security\n\n"
};

static int g_elf_file_header_flag = 0;
static int g_elf_prog_header_flag = 0;
static int g_elf_help_flag = 0;

int
main(int argc, char** argv)
{
        void* data;
        const char* binpath;
        size_t datasz;
        Elf64_Ehdr ehdr;
        int c, option_index;

        while (1) {
                option_index = 0;
                static struct option long_options[] = {
                    {"file-header",     no_argument, 0, 'h' },
                    {"program-headers", no_argument, 0, 'l' },
                    {"segments",        no_argument, 0, 'l' },
                    {"help",            no_argument, 0, 'H' },
                    { 0,                0,           0,  0  }
                };

                c = getopt_long(argc, argv, "hlH",
                        long_options, &option_index);
                if (c == -1) {
                        g_elf_help_flag = optind == 1 ? optind : g_elf_help_flag;
                        break;
                }

                switch (c) {
                case 'h':
                        g_elf_file_header_flag = 1;
                        break;
                case 'l':
                        g_elf_prog_header_flag = 1;
                        break;
                case 'H':
                case '?':
                default:
                        g_elf_help_flag = 1;
                }
        }

        if (optind + 1 == argc)
                binpath = argv[optind];
        else
                g_elf_help_flag = 1;

        if (g_elf_help_flag)
                err_exit(g_help_menu);

        if (read_file_into_mem(binpath, &data, &datasz) == 0)
                err_exit("* read_file_into_mem() error");

        if (datasz < sizeof(Elf64_Ehdr))
                err_exit("* not an ordinary file");

        memcpy(&ehdr, data, sizeof(Elf64_Ehdr));
        if (strncmp(ELFMAG, (const char*)&ehdr.e_ident[EI_MAG0], SELFMAG) != 0)
                err_exit("* Error: Not an ELF file - it has the wrong magic bytes at the start");

        if (g_elf_file_header_flag)
                display_elf_header(&ehdr);

        free(data);
        return 0;
}


void
display_elf_header(const Elf64_Ehdr* ehdr)
{
        unsigned char elf_ei_osabi, elf_ei_data, elf_ei_class;
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

        elf_ei_class = ehdr->e_ident[EI_CLASS];
        if (elf_ei_class < ELFCLASS32 || elf_ei_class > ELFCLASS64)
                elf_ei_class = ELFCLASSNONE;

        elf_ei_data = ehdr->e_ident[EI_DATA];
        if (elf_ei_data < ELFDATA2LSB || elf_ei_data > ELFDATA2MSB)
                elf_ei_data = ELFDATANONE;

        elf_ei_osabi = ehdr->e_ident[EI_OSABI];
        if (elf_ei_osabi >= ELFOSABI_SOLARIS && elf_ei_osabi <= ELFOSABI_OPENBSD)
                elf_ei_osabi -= 2;
        else if (elf_ei_osabi >= ELFOSABI_ARM_AEABI)
                elf_ei_osabi = (ARRAY_SIZE(elf_osabi_id) - 1);

        elf_e_type = ehdr->e_type;
        if (elf_e_type > 5 && elf_e_type < ET_LOOS)
                elf_e_type = ET_NONE;
        else if (elf_e_type >= ET_LOOS && elf_e_type <= ET_HIOS)
                elf_e_type = INDEX_ET_OS;
        else if (elf_e_type >= ET_HIOS && elf_e_type <= ET_LOPROC)
                elf_e_type = INDEX_ET_PROC;

        elf_e_version = ehdr->e_version != EV_CURRENT ? EV_NONE : ehdr->e_version;

        printf(
                "ELF Header:\n"
                "  Magic:   "
        );
        for (int i = 0; i < EI_NIDENT; i++)
                printf("%.2x ", ehdr->e_ident[i]);
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
                (int)ehdr->e_ident[EI_VERSION],
                elf_osabi_id[elf_ei_osabi],
                (int)ehdr->e_ident[EI_ABIVERSION],
                elf_e_type_id[elf_e_type],
                ehdr->e_machine >= EM_NUM ? "special\n" : elf_e_machine_id[ehdr->e_machine],
                ehdr->e_version, elf_e_version_id[elf_e_version],
                (int)ehdr->e_entry, (int)ehdr->e_phoff, (int)ehdr->e_shoff, (int)ehdr->e_flags, (int)ehdr->e_ehsize,
                (int)ehdr->e_phentsize, (int)ehdr->e_phnum, (int)ehdr->e_shentsize, (int)ehdr->e_shnum, (int)ehdr->e_shstrndx
        );
}


int
read_file_into_mem(const char* filename, void** data_out, size_t* size_out)
{
        struct stat sb;
        FILE* file;
        long filesize;
        void* mem;

        if ((stat(filename, &sb) == -1) || S_ISDIR(sb.st_mode))
                goto err_ret;

        file = fopen(filename, "rb");
        if (file == NULL)
                goto err_ret;

        if (fseek(file, 0, SEEK_END) == -1)
                goto err_close;

        errno = 0;
        filesize = ftell(file);
        if (filesize == -1L || errno != 0)
                goto err_close;
        rewind(file);

        mem = malloc(filesize);
        if (mem == NULL)
                goto err_close;

        if (fread(mem, filesize, 1, file) != 1)
                goto err_free;

        fclose(file);

        *data_out = mem;
        *size_out = filesize;

        return 1;
err_free:
        free(mem);
err_close:
        fclose(file);
err_ret:
        return 0;
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
