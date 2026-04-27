# include <stdio.h>
# include <stdlib.h>

void PrintHex(const unsigned char *buffer, size_t length)
{
    size_t i;
    for (i = 0; i < length; i++)
    {
        printf("%02x", buffer[i]);
    }
}

int main(int argc, char **argv)
{
    const char *filename;
    FILE *fp;
    unsigned char buffer[1024];
    size_t bytes_read;

    if (argc != 2)
    {
        fprintf(stderr, "Usage %s FILE\n", argv[0]);
        return 1;
    }

    filename = argv[1];

    fp = fopen(filename, "rb");
    if (fp == NULL)
    {
        perror("error opening file");
        return 1;
    }


    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0)
    {
        PrintHex(buffer, bytes_read);
    }
    printf("\n");
    fclose(fp);
    return 0;
}