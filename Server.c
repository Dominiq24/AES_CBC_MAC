#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define FRAGMENT_SIZE 100
#define MAX_FRAGMENTS 10

// Function to break a message into fragments with proper indexing
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

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    char mac_buffer[16];
    char *fragments[MAX_FRAGMENTS]; // Array to store fragments
    int fragmentCount = 0;

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    
    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    // Bind the socket to localhost port 8080
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    
    // Accept the incoming connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    // Receive fragments and MAC from the client
    while (1) {
        int valread = recv(new_socket, buffer, BUFFER_SIZE, 0);
        if (valread <= 0)
            break;
        buffer[valread] = '\0';
        printf("Fragment received: %s\n", buffer);
        
        // Store the received fragment in a text file
        char fragment_filename[50];
        snprintf(fragment_filename, sizeof(fragment_filename), "Fragment_%d.txt", fragmentCount);
        FILE *fragment_file = fopen(fragment_filename, "w");
        if (fragment_file == NULL) {
            perror("Error creating fragment file");
            exit(EXIT_FAILURE);
        }
        fprintf(fragment_file, "%s", buffer);
        fclose(fragment_file);

        fragments[fragmentCount] = strdup(buffer); // Store the received fragment

        // Receive MAC for the fragment
        valread = recv(new_socket, mac_buffer, 16, 0);
        if (valread <= 0)
            break;
        mac_buffer[valread] = '\0';
        printf("MAC received for fragment %d: ", fragmentCount);
        for (int j = 0; j < 16; j++) {
            printf("%02x", (unsigned char)mac_buffer[j]);
        }
        printf("\n");

        // Store the received MAC in a text file
        char mac_filename[50];
        snprintf(mac_filename, sizeof(mac_filename), "MAC_%d.txt", fragmentCount);
        FILE *mac_file = fopen(mac_filename, "w");
        if (mac_file == NULL) {
            perror("Error creating MAC file");
            exit(EXIT_FAILURE);
        }
        for (int j = 0; j < 16; j++) {
            fprintf(mac_file, "%02x", (unsigned char)mac_buffer[j]);
        }
        fclose(mac_file);

        fragmentCount++;
    }

    // Close the socket
    close(new_socket);
    close(server_fd);

    // Process the stored fragments as needed
    for (int i = 0; i < fragmentCount; i++) {
        printf("Fragment %d: %s\n", i, fragments[i]);
        free(fragments[i]); // Free dynamically allocated memory
    }

    return 0;
}
