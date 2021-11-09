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
        bool status;

        const char* elf_class_id[ELFCLASSNUM] = {
                "NONE",
                "ELF32",
                "ELF64"
        };

        const char* elf_data_id[ELFDATANUM] = {
                "Invalid data encoding",
                "2's complement, little endian",
                "2's complement, big endian"
        };

        const char* elf_osabi_id[] = {
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

        const char* elf_e_type_id[] = {
                "NONE No file type",
                "REL Relocatable file",
                "EXEC Executable file",
                "DYN Shared object file",
                "CORE Core file",
                "NUM Number of defined types",
                "OS-specific range",
                "Processor-specific range"
        };

        const char* elf_e_machine_id[EM_NUM] = {
                "No machine",
                "AT&T WE 32100",
                "SUN SPARC",
                "Intel 80386",
                "Motorola m68k family",
                "Motorola m88k family",
                "Intel MCU",
                "Intel 80860",
                "MIPS R3000 big-endian",
                "IBM System/370",
                "MIPS R3000 little-endian",
                "reserved","reserved","reserved","reserved",
                "HPPA",
                "reserved",
                "Fujitsu VPP500",
                "Sun's v8plus",
                "Intel 80960",
                "PowerPC","PowerPC 64-bit",
                "IBM S390","IBM SPU/SPC",
                "reserved","reserved","reserved","reserved","reserved",
                "reserved","reserved","reserved","reserved","reserved",
                "reserved","reserved",
                "NEC V800 series",
                "Fujitsu FR20",
                "TRW RH-32",
                "Motorola RCE",
                "ARM",
                "Digital Alpha",
                "Hitachi SH",
                "SPARC v9 64-bit",
                "Siemens Tricore",
                "Argonaut RISC Core",
                "Hitachi H8/300","Hitachi H8/300H","Hitachi H8S","Hitachi H8/500",
                "Intel Merced",
                "Stanford MIPS-X",
                "Motorola Coldfire","Motorola M68HC12",
                "Fujitsu MMA Multimedia Accelerator",
                "Siemens PCP",
                "Sony nCPU embeeded RISC",
                "Denso NDR1 microprocessor",
                "Motorola Start*Core processor",
                "Toyota ME16 processor",
                "STMicroelectronic ST100 processor",
                "Advanced Logic Corp. Tinyj emb.fam",
                "AMD x86-64 architecture",
                "Sony DSP Processor",
                "Digital PDP-10","Digital PDP-11",
                "Siemens FX66 microcontroller",
                "STMicroelectronics ST9+ 8/16 mc","STmicroelectronics ST7 8 bit mc",
                "Motorola MC68HC16 microcontroller","Motorola MC68HC11 microcontroller","Motorola MC68HC08 microcontroller","Motorola MC68HC05 microcontroller",
                "Silicon Graphics SVx",
                "STMicroelectronics ST19 8 bit mc",
                "Digital VAX",
                "Axis Communications 32-bit emb.proc",
                "Infineon Technologies 32-bit emb.proc",
                "Element 14 64-bit DSP Processor",
                "LSI Logic 16-bit DSP Processor",
                "Donald Knuth's educational 64-bit proc",
                "Harvard University machine-independent object files",
                "SiTera Prism",
                "Atmel AVR 8-bit microcontroller",
                "Fujitsu FR30",
                "Mitsubishi D10V","Mitsubishi D30V",
                "NEC v850",
                "Mitsubishi M32R","Matsushita MN10300","Matsushita MN10200",
                "picoJava",
                "OpenRISC 32-bit embedded processor",
                "ARC International ARCompact",
                "Tensilica Xtensa Architecture",
                "Alphamosaic VideoCore",
                "Thompson Multimedia General Purpose Proc",
                "National Semi. 32000",
                "Tenor Network TPC",
                "Trebia SNP 1000",
                "STMicroelectronics ST200",
                "Ubicom IP2xxx",
                "MAX processor",
                "National Semi. CompactRISC",
                "Fujitsu F2MC16",
                "Texas Instruments msp430",
                "Analog Devices Blackfin DSP",
                "Seiko Epson S1C33 family",
                "Sharp embedded microprocessor",
                "Arca RISC",
                "PKU-Unity & MPRC Peking Uni. mc series",
                "eXcess configurable cpu",
                "Icera Semi. Deep Execution Processor",
                "Altera Nios II",
                "National Semi. CompactRISC CRX",
                "Motorola XGATE",
                "Infineon C16x/XC16x",
                "Renesas M16C",
                "Microchip Technology dsPIC30F",
                "Freescale Communication Engine RISC",
                "Renesas M32C",
                "reserved","reserved","reserved","reserved","reserved",
                "reserved","reserved","reserved","reserved","reserved",
                "Altium TSK3000",
                "Freescale RS08",
                "Analog Devices SHARC family",
                "Cyan Technology eCOG2",
                "Sunplus S+core7 RISC",
                "New Japan Radio (NJR) 24-bit DSP",
                "Broadcom VideoCore III",
                "RISC for Lattice FPGA",
                "Seiko Epson C17",
                "Texas Instruments TMS320C6000 DSP","Texas Instruments TMS320C2000 DSP","Texas Instruments TMS320C55x DSP",
                "Texas Instruments App. Specific RISC","Texas Instruments Prog. Realtime Unit",
                "reserved","reserved","reserved","reserved","reserved",
                "reserved","reserved","reserved","reserved","reserved",
                "reserved","reserved","reserved","reserved","reserved",
                "STMicroelectronics 64bit VLIW DSP",
                "Cypress M8C",
                "Renesas R32C",
                "NXP Semi. TriMedia",
                "QUALCOMM DSP6",
                "Intel 8051 and variants",
                "STMicroelectronics STxP7x",
                "Andes Tech. compact code emb. RISC",
                "Cyan Technology eCOG1X",
                "Dallas Semi. MAXQ30 mc",
                "New Japan Radio (NJR) 16-bit DSP",
                "M2000 Reconfigurable RISC",
                "Cray NV2 vector architecture",
                "Renesas RX",
                "Imagination Tech. META",
                "MCST Elbrus",
                "Cyan Technology eCOG16",
                "National Semi. CompactRISC CR16",
                "Freescale Extended Time Processing Unit",
                "Infineon Tech. SLE9X",
                "Intel L10M","Intel K10M",
                "reserved",
                "ARM AARCH64",
                "reserved",
                "Amtel 32-bit microprocessor",
                "STMicroelectronics STM8",
                "Tileta TILE64","Tilera TILEPro",
                "Xilinx MicroBlaze",
                "NVIDIA CUDA",
                "Tilera TILE-Gx",
                "CloudShield",
                "KIPO-KAIST Core-A 1st gen.","KIPO-KAIST Core-A 2nd gen.",
                "Synopsys ARCv2 ISA. ",
                "Open8 RISC",
                "Renesas RL78",
                "Broadcom VideoCore V",
                "Renesas 78KOR",
                "Freescale 56800EX DSC",
                "Beyond BA1","Beyond BA2",
                "XMOS xCORE",
                "Mielf_e_versioncrochip 8-bit PIC(r)",
                "reserved", "reserved", "reserved", "reserved", "reserved",
                "KM211 KM32","KM211 KMX32","KM211 KMX16","KM211 KMX8","KM211 KVARC",
                "Paneve CDP",
                "Cognitive Smart Memory Processor",
                "Bluechip CoolEngine",
                "Nanoradio Optimized RISC",
                "CSR Kalimba",
                "Zilog Z80",
                "Controls and Data Services VISIUMcore",
                "FTDI Chip FT32",
                "Moxie processor",
                "AMD GPU",
                "reserved","reserved","reserved","reserved","reserved",
                "reserved","reserved","reserved","reserved","reserved",
                "reserved","reserved","reserved","reserved","reserved",
                "reserved","reserved","reserved",
                "RISC-V",
                "unspecified","unspecified","unspecified",
                "Linux BPF -- in-kernel virtual machine",
                "unspecified","unspecified","unspecified","unspecified",
                "C-SKY"
        };

        const char* elf_e_version_id[EV_NUM] = {
                "Invalid ELF version",
                "Current version"
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
                "  Version:                             0x%.8x(%s)\n"
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
                elf_class_id[elf_ei_class],
                elf_data_id[elf_ei_data],
                ehdr.e_ident[EI_VERSION],
                elf_osabi_id[elf_ei_osabi],
                ehdr.e_ident[EI_ABIVERSION], // Further specifies the ABI version.
                                             // Its interpretation depends on the target ABI.
                                             // Linux kernel (after at least 2.6) has no definition of it,
                                             // so it is ignored for statically-linked executables.
                                             // In that case, offset and size of EI_PAD are 8.
                elf_e_type_id[elf_e_type],
                ehdr.e_machine >= EM_NUM ? "special\n" : elf_e_machine_id[ehdr.e_machine],
                ehdr.e_version, elf_e_version_id[elf_e_version]
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
