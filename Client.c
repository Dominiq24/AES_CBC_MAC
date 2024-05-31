#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define FRAGMENT_SIZE 100
#define FRAGMENT_COUNT 10

void breakMessage(char *message, char *fragments[], int *fragmentCount) {
    int messageLength = strlen(message);
    int fragmentIndex = 0;
    for (int i = 0; i < messageLength; i += FRAGMENT_SIZE) {
        fragments[fragmentIndex] = (char *)malloc(BUFFER_SIZE * sizeof(char));
        snprintf(fragments[fragmentIndex], BUFFER_SIZE, "%d:%.*s", fragmentIndex, FRAGMENT_SIZE, message + i);
        (*fragmentCount)++;
        fragmentIndex++;
    }
}

void computeMAC(const unsigned char *message, int messageLength, unsigned char *mac, const unsigned char *key, const unsigned char *iv) {
    AES_KEY encKey;
    AES_set_encrypt_key(key, 128, &encKey);
    AES_cbc_encrypt(message, mac, messageLength, &encKey, iv, AES_ENCRYPT);
}

void freeFragments(char *fragments[], int fragmentCount) {
    for (int i = 0; i < fragmentCount; i++) {
        free(fragments[i]);
    }
}

void printFileContent(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }
    
    char buffer[BUFFER_SIZE];
    while (fgets(buffer, BUFFER_SIZE, file) != NULL) {
        printf("%s", buffer);
    }
    
    fclose(file);
}

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char file_buffer[BUFFER_SIZE];
    FILE *file;
    size_t bytesRead;
    char filename[100];
    char iv[17];
    char key[17];
    unsigned char mac[16];
    unsigned char computedMac[16];
    int fragmentCount = 0;
    int choice;
    char *fragments[FRAGMENT_COUNT];  // Declare fragments array here

    printf("Enter the IV (16 bytes in hexadecimal format): ");
    fgets(iv, sizeof(iv), stdin);
    iv[strcspn(iv, "\n")] = 0;

    unsigned char binaryIV[16];
    for (int i = 0; i < 16; i++) {
        sscanf(iv + 2 * i, "%2hhx", &binaryIV[i]);
    }

    printf("Enter the key (16 bytes in hexadecimal format): ");
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = 0;

    unsigned char binaryKey[16];
    for (int i = 0; i < 16; i++) {
        sscanf(key + 2 * i, "%2hhx", &binaryKey[i]);
    }

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket creation error");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        exit(EXIT_FAILURE);
    }

    while (1) {
        printf("Choose an option:\n");
        printf("1. Send file fragments with MAC\n");
        printf("2. Compute AES CBC MAC for a file\n");
        printf("3. Compare two MACs\n");
        printf("4. Exit\n");
        scanf("%d", &choice);
        getchar(); // consume newline character

        switch (choice) {
            case 1:
                printf("Enter the filename: ");
                fgets(filename, sizeof(filename), stdin);
                filename[strcspn(filename, "\n")] = 0;

                file = fopen(filename, "r");
                if (file == NULL) {
                    perror("Error opening file");
                    break;
                }
                bytesRead = fread(file_buffer, 1, BUFFER_SIZE, file);
                fclose(file);

                breakMessage(file_buffer, fragments, &fragmentCount);
                for (int i = 0; i < fragmentCount; i++) {
                    computeMAC((const unsigned char *)fragments[i], strlen(fragments[i]), mac, binaryKey, binaryIV);
                    printf("Fragment %d: %s\n", i + 1, fragments[i]);
                    printf("MAC for fragment %d: ", i + 1);
                    for (int j = 0; j < 16; j++) {
                        printf("%02x", mac[j]);
                    }
                    printf("\n");
                    send(sock, fragments[i], strlen(fragments[i]), 0);
                    usleep(10000);  // sleep to avoid sending the MAC before the fragment is received by the server
                    send(sock, mac, 16, 0);
                    usleep(10000);
                }
                break;

            case 2:
                printf("Enter the filename to compute AES CBC MAC for: ");
                fgets(filename, sizeof(filename), stdin);
                filename[strcspn(filename, "\n")] = 0;

                file = fopen(filename, "r");
                if (file == NULL) {
                    perror("Error opening file");
                    break;
                }
                bytesRead = fread(file_buffer, 1, BUFFER_SIZE, file);
                fclose(file);

                computeMAC((const unsigned char *)file_buffer, bytesRead, computedMac, binaryKey, binaryIV);
                printf("Computed AES CBC MAC for the file: ");
                for (int i = 0; i < 16; i++) {
                    printf("%02x", computedMac[i]);
                }
                printf("\n");
                break;

            case 3:
                printf("Enter the filename to compare MACs and print its content: ");
                fgets(filename, sizeof(filename), stdin);
                filename[strcspn(filename, "\n")] = 0;

                printf("File content:\n");
                printFileContent(filename);

                printf("\nEnter the first MAC (16 bytes in hexadecimal format): ");
                fgets(mac, sizeof(mac), stdin);
                mac[strcspn(mac, "\n")];
                printf("\nEnter the second MAC (16 bytes in hexadecimal format): ");
                fgets(computedMac, sizeof(computedMac), stdin);
                computedMac[strcspn(computedMac, "\n")] = 0;

                if (memcmp(mac, computedMac, 16) == 0) {
                    printf("MACs are equal.\n");
                } else {
                    printf("MACs are not equal.\n");
                }
                break;

            case 4:
                close(sock);
                freeFragments(fragments, fragmentCount);
                exit(EXIT_SUCCESS);
                break;

            default:
                printf("Invalid choice.\n");
                break;
        }
    }

    return 0;
}
