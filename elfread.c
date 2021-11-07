/* elfread.c
 * the-scientist@rootstorm.com
 * spl0its-r-us security
 */

 /*
 * NOTES: 
 *#include <elf.h> just reading the source
 *the best way to learn is to read the fuckin structs make a program that reads in an elf
 *start off by reading in an Elf_Ehdr gotta know what kind of elf file it is before actually 
 *trying to interpret the data past the magic ehdr->e_ident[EI_CLASS] can be either ELFCLASS64 or ELFCLASS32
 *depending on this everything thereon will be an Elf32_blah or an Elf64_blah
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h> 
#include <inttypes.h>
#include <stdlib.h>

int
read_file_into_mem(const char* filename, void** data_out, size_t* size_out);
int
write_mem_to_file(const char* filename, const void* data, size_t size);

int
main(int argc, char** argv)
{
    uint8_t* data;
    size_t datasz;

    read_file_into_mem("ls", (void**)&data, &datasz);
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
