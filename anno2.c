#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_SIZE 256

// Hardcoded password - CWE-798
const char *ADMIN_PASSWORD = "SuperSecret123";

// Insecure function usage - CWE-120 (Buffer Overflow)
void unsafe_copy(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Unsafe: no bounds checking
    printf("Buffer content: %s\n", buffer);
}

// Command injection - CWE-78
void run_command(char *input) {
    char command[128];
    snprintf(command, sizeof(command), "ls %s", input);  // Input not sanitized
    system(command);  // Dangerous: user input in system call
}

// Format string vulnerability - CWE-134
void print_user_input(char *input) {
    printf(input);  // Unsafe: input used directly as format string
}

// Path traversal - CWE-22
void read_file(char *filename) {
    char path[256];
    snprintf(path, sizeof(path), "/tmp/%s", filename);  // No validation
    FILE *file = fopen(path, "r");
    if (file) {
        char line[MAX_SIZE];
        while (fgets(line, MAX_SIZE, file)) {
            printf("%s", line);
        }
        fclose(file);
    } else {
        printf("File not found.\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    char *input = argv[1];

    unsafe_copy(input);
    run_command(input);
    print_user_input(input);
    read_file(input);

    return 0;
}
