#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct virus
{
    unsigned short SigSize;
    unsigned char *VirusName;
    unsigned char *Sig;

} virus;


typedef struct link link;
struct link
{
    link *next;
    virus *vir;
};

static link *virus_list = NULL;
static char selected_filename[256] = {0};
typedef enum
{
    ENDIAN_UNKNOWN = 0,
    ENDIAN_LITTLE,
    ENDIAN_BIG

} endian_t;

static endian_t file_endian = ENDIAN_UNKNOWN;

virus *readVirus(FILE *file)
{
    unsigned char size_bytes[2];
    virus *v;
    unsigned short size;
    size_t read_count;

    read_count = fread(size_bytes, 1, 2, file);
    if (read_count != 2)
    {
        return NULL;
    }

    if (file_endian == ENDIAN_LITTLE)
    {
        size = (unsigned short) (size_bytes[0] | (size_bytes[1] << 8));
    }
    else if (file_endian == ENDIAN_BIG)
    {
        size = (unsigned short) (size_bytes[0] << 8 | (size_bytes[1]));
    }
    else
    {
        return NULL;
    }

    v = (virus *) malloc(sizeof(virus));
    if (v == NULL)
    {
        fprintf(stderr, "malloc failed\n");
        return NULL;
    }

    v->SigSize = size;
    v->VirusName = NULL;
    v->Sig = NULL;

    v->VirusName = (unsigned char *) malloc(16);
    if (v->VirusName == NULL)
    {
        fprintf(stderr, "malloc failed\n");
        free(v);
        return NULL;
    }

    read_count = fread(v->VirusName, 1, 16, file);
    if (read_count != 16)
    {
        printf("Error reading Virus name\n");
        free(v->VirusName);
        free(v);
        return NULL;
    }

    v->Sig = (unsigned char *) malloc(v->SigSize);
    if (v->Sig == NULL)
    {
        fprintf(stderr, "malloc failed\n");
        free(v->VirusName);
        free(v);
        return NULL;
    }
    read_count = fread(v->Sig, 1, v->SigSize, file);
    if (read_count != v->SigSize)
    {
        printf("Error reading virus signature\n");
        free(v->Sig);
        free(v->VirusName);
        free(v);
        return NULL;
    }

    return v;
}

void printVirus(virus *v, FILE *output)
{
    size_t i;
    if (v == NULL)
    {
        return;
    }
    fprintf(output, "Virus Name: %s\n", v->VirusName);
    fprintf(output, "Virus Size: %hu\n", v->SigSize);
    fprintf(output, "signature: \n");

    for (i = 0; i < v->SigSize; i++)
    {
        fprintf(output, "%02X", v->Sig[i]);
        if ((i + 1) % 16 == 0)
        {
            fprintf(output, "\n");
        }
    }
    if (v->SigSize % 16 != 0)
        fprintf(output, "\n");
}


link *list_append(link *virus_list_head, virus *data)
{
    link *new_node = (link *) malloc(sizeof(link));
    if (new_node == NULL)
    {
        fprintf(stderr, "malloc failed\n");
        return virus_list_head;
    }
    new_node->vir = data;
    new_node->next = NULL;

    if (virus_list_head == NULL)
        return new_node;

    link *curr = virus_list_head;
    while (curr->next != NULL)
        curr = curr->next;

    curr->next = new_node;
    return virus_list_head;
}


void list_print(link *virus_list_head, FILE *output)
{
    link *curr = virus_list_head;
    while (curr != NULL)
    {
        printVirus(curr->vir, output);
        fprintf(output, "\n");
        curr = curr->next;
    }
}

void list_free(link *virus_list_head)
{
    link *curr = virus_list_head;
    while (curr != NULL)
    {
        link *next = curr->next;
        if (curr->vir != NULL)
        {
            free(curr->vir->VirusName);
            free(curr->vir->Sig);
            free(curr->vir);
        }
        free(curr);
        curr = next;
    }
}

void detect_virus(char *buffer, unsigned int size, link *virus_list_head)
{
    link *curr = virus_list_head;

    while (curr != NULL)
    {
        virus *v = curr->vir;
        unsigned int i;

        if (v != NULL && v->SigSize > 0 && v->SigSize <= size)
        {
            for (i = 0; i <= size - v->SigSize; ++i)
            {
                /* Compare the buffer window with the virus signature. */
                if (memcmp(buffer + i, v->Sig, v->SigSize) == 0)
                {
                    printf("Virus found at offset: %u\n", i);
                    printf("Virus name: %s\n", v->VirusName);
                    printf("Virus size: %hu\n\n", v->SigSize);
                }
            }
        }

        curr = curr->next;
    }
}

void neutralize_virus(const char *filename, int signatureOffset)
{
    FILE *fp;
    unsigned char ret_opcode = 0xC3;

    if (filename == NULL || filename[0] == '\0')
    {
        printf("neutralize_virus: invalid file name.\n");
        return;
    }

    fp = fopen(filename, "r+b");
    if (fp == NULL)
    {
        perror("Error opening file for neutralization");
        return;
    }


    if (fseek(fp, signatureOffset, SEEK_SET) != 0)
    {
        perror("Error seeking in file");
        fclose(fp);
        return;
    }


    if (fwrite(&ret_opcode, 1, 1, fp) != 1)
    {
        perror("Error writing RET opcode");
    }

    fflush(fp);
    fclose(fp);
}

void load_signature_menu()
{
    char filename[256];
    FILE *fp;
    unsigned char magic[4];
    size_t read_count;

    if (virus_list != NULL)
    {
        list_free(virus_list);
        virus_list = NULL;
    }

    printf("enter signature file name: ");

    if (fgets(filename, sizeof(filename), stdin) == NULL)
    {
        printf("failed to read file name");
        return;
    }
    filename[strcspn(filename, "\n")] = '\0';

    fp = fopen(filename, "rb");
    if (fp == NULL)
    {
        perror("error opening signature file");
        return;
    }

    read_count = fread(magic, 1, 4, fp);
    if (read_count != 4)
    {
        printf("ERROR: signature file too short (no magic number");
        fclose(fp);
        return;
    }

    if (memcmp(magic, "VIRL", 4) == 0)
    {
        file_endian = ENDIAN_LITTLE;
    }
    else if (memcmp(magic, "VIRB", 4) == 0)
    {
        file_endian = ENDIAN_BIG;
    }
    else
    {
        printf("ERROR: bad magic number in signature file.\n");
        fclose(fp);
        return;
    }

    while (1)
    {
        virus *v = readVirus(fp);
        if (v == NULL)
            break;
        virus_list = list_append(virus_list, v);
    }

    fclose(fp);
    printf("Signature loaded. \n");
}

void print_signature_menu()
{
    if (virus_list == NULL)
    {
        printf("No signatures loaded.\n");
        return;
    }

    list_print(virus_list, stdout);
}

void select_file_menu()
{
    char input[256];

    printf("Enter file name to inspect: ");

    if (fgets(input, sizeof(input), stdin) == NULL)
    {
        printf("Failed to read file name.\n");
        return;
    }

    input[strcspn(input, "\n")] = '\0';

    if (input[0] == '\0')
    {
        printf("Empty file name.\n");
        return;
    }

    strncpy(selected_filename, input, sizeof(selected_filename) - 1);
    selected_filename[sizeof(selected_filename) - 1] = '\0';

    printf("Selected file: %s\n", selected_filename);
}

void detect_viruses_menu()
{
    if (virus_list == NULL)
    {
        printf("No signatures loaded.\n");
        return;
    }

    if (selected_filename[0] == '\0')
    {
        printf("No file selected. Use option 3 first.\n");
        return;
    }

    FILE *fp = fopen(selected_filename, "rb");
    if (fp == NULL)
    {
        perror("Error opening selected file");
        return;
    }

    char buffer[10000];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), fp);
    if (bytes_read == 0)
    {
        printf("Failed to read from selected file.\n");
        fclose(fp);
        return;
    }

    fclose(fp);

    detect_virus(buffer, (unsigned int)bytes_read, virus_list);
}

void fix_file_menu()
{
    if (virus_list == NULL)
    {
        printf("No signatures loaded.\n");
        return;
    }

    if (selected_filename[0] == '\0')
    {
        printf("No file selected. Use option 3 first.\n");
        return;
    }

    FILE *fp = fopen(selected_filename, "r+b");
    if (fp == NULL)
    {
        perror("Error opening selected file for fixing");
        return;
    }

    char buffer[10000];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), fp);
    if (bytes_read == 0)
    {
        printf("Failed to read from selected file.\n");
        fclose(fp);
        return;
    }


    fclose(fp);

    link *curr = virus_list;
    while (curr != NULL)
    {
        virus *v = curr->vir;
        unsigned int i;

        if (v != NULL && v->SigSize > 0 && v->SigSize <= bytes_read)
        {
            for (i = 0; i <= bytes_read - v->SigSize; ++i)
            {
                if (memcmp(buffer + i, v->Sig, v->SigSize) == 0)
                {
                    printf("Neutralizing virus '%s' at offset %u\n",
                           v->VirusName, i);
                    neutralize_virus(selected_filename, (int)i);
                }
            }
        }

        curr = curr->next;
    }
}

void print_menu()
{

    printf("Please choose an option:\n");
    printf("1) Load signatures\n");
    printf("2) Print signatures\n");
    printf("3) Select file to inspect\n");
    printf("4) Detect viruses\n");
    printf("5) Fix file\n");
    printf("6) Quit\n");
}

int main(int argc, char **argv)
{
    char input[256];
    int choice = 0;
    (void)argc;
    (void)argv;

    while (1)
    {
        print_menu();
        printf("Option: ");
        if (fgets(input, sizeof(input), stdin) == NULL)
        {
            break;

        }
        if (sscanf(input, "%d", &choice) != 1)
        {
            printf("Invalid input\n");
            continue;
        }
        switch (choice)
        {
        case 1:
            load_signature_menu();
            break;
        case 2:
            print_signature_menu();
            break;
        case 3:
            select_file_menu();
            break;
        case 4:
            detect_viruses_menu();
            break;
        case 5:
            fix_file_menu();
            break;
        case 6:
            list_free(virus_list);
            virus_list = NULL;
            return 0;
        default:
            printf("Invalid choice\n");
            break;
        }
        printf("\n");
    }
    list_free(virus_list);
    virus_list = NULL;
    return 0;
}