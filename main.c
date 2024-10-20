/*!
 * \file main.c
 * \brief Основной и единственный файл.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define KEY_LENGTH 32
#define IV_LENGTH 16

/*!
 * \brief Выводит сообщение о способе использования программы.
 *
 * \param prog_name Имя исполняемого файла программы.
 */
void print_usage(const char *prog_name) {
    printf("Usage: %s -e|-d -i <input file> -o <output file> -p <password>\n", prog_name);
}

/*!
 * \brief Вычисляет ключ и вектор инициализации на основе пароля. Используется SHA512, иначе длинна ключа+вектора инициализации вылезет за границу массива и в расшиврованном сообщении будет мусор.
 *
 * \param password Пароль для выработки ключа.
 * \param key Буфер для хранения ключа.
 * \param iv Буфер для хранения вектора инициализации.
 * \return Возвращает 0 при успешном выполнении.
 */
int derive_key_iv(const char *password, unsigned char *key, unsigned char *iv) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512((unsigned char*)password, strlen(password), hash);
    memcpy(key, hash, KEY_LENGTH);
    memcpy(iv, hash + KEY_LENGTH, IV_LENGTH);
    return 0;
}

/*!
 * \brief Шифрует входной файл и записывает данные в выходной файл.
 *
 * \param in_filename Путь к входному файлу.
 * \param out_filename Путь к выходному файлу.
 * \param password Пароль для шифрования.
 * \return Возвращает 0 при успешном шифровании, иначе 1.
 */
int encrypt_file(const char *in_filename, const char *out_filename, const char *password) {
    FILE *in_file = fopen(in_filename, "rb");
    if (!in_file) {
        printf("Failed to open input file\n");
        return 1;
    }

    FILE *out_file = fopen(out_filename, "wb");
    if (!out_file) {
        printf("Failed to open output file\n");
        fclose(in_file);
        return 1;
    }

    unsigned char key[KEY_LENGTH];
    unsigned char iv[IV_LENGTH];
    derive_key_iv(password, key, iv);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Failed to create encryption context\n");
        fclose(in_file);
        fclose(out_file);
        return 1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        printf("Encryption initialization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in_file);
        fclose(out_file);
        return 1;
    }

    unsigned char buffer[4096];
    unsigned char out_buffer[4096 + EVP_MAX_BLOCK_LENGTH];
    memset(out_buffer, 0, 4096 + EVP_MAX_BLOCK_LENGTH);
    memset(buffer, 0, 4096);
    int out_len;

    while ((out_len = fread(buffer, 1, sizeof(buffer), in_file)) > 0) {
        if (EVP_EncryptUpdate(ctx, out_buffer, &out_len, buffer, out_len) != 1) {
            printf("Encryption error\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in_file);
            fclose(out_file);
            return 1;
        }
        fwrite(out_buffer, 1, out_len, out_file);
    }

    if (EVP_EncryptFinal(ctx, out_buffer, &out_len) != 1) {
        printf("Final encryption step failed\n");
        fclose(in_file);
        fclose(out_file);
        return 1;
    }
    fwrite(out_buffer, 1, out_len, out_file);
    fflush(out_file);

    fclose(in_file);
    fclose(out_file);
    return 0;
}

/*!
 * \brief Расшифровывает входной файл и записывает данные в выходной файл.
 *
 * \param in_filename Путь к зашифрованному файлу.
 * \param out_filename Путь к выходному файлу.
 * \param password Пароль для расшифровки.
 * \return Возвращает 0 при успешном расшифровании, иначе 1.
 */
int decrypt_file(const char *in_filename, const char *out_filename, const char *password) {
    FILE *in_file = fopen(in_filename, "rb");
    if (!in_file) {
        printf("Failed to open input file\n");
        return 1;
    }

    FILE *out_file = fopen(out_filename, "wb");
    if (!out_file) {
        printf("Failed to open output file\n");
        fclose(in_file);
        return 1;
    }

    unsigned char key[KEY_LENGTH];
    unsigned char iv[IV_LENGTH];
    derive_key_iv(password, key, iv);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("Failed to create decryption context\n");
        fclose(in_file);
        fclose(out_file);
        return 1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        printf("Decryption initialization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in_file);
        fclose(out_file);
        return 1;
    }

    unsigned char buffer[4096];
    unsigned char out_buffer[4096 + EVP_MAX_BLOCK_LENGTH];
    memset(out_buffer, 0, 4096 + EVP_MAX_BLOCK_LENGTH);
    memset(buffer, 0, 4096);
    int out_len;

    while ((out_len = fread(buffer, 1, 4096, in_file)) > 0) {
        if (EVP_DecryptUpdate(ctx, out_buffer, &out_len, buffer, out_len) != 1) {
            printf("Decryption error\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in_file);
            fclose(out_file);
            return 1;
        }
        fwrite(out_buffer, 1, out_len, out_file);
    }

    if (EVP_DecryptFinal(ctx, out_buffer, &out_len) != 1) {
        printf("Final decryption step failed\n");
        fclose(in_file);
        fclose(out_file);
        return 1;
    }
    fwrite(out_buffer, 1, out_len, out_file);
    fflush(out_file);
    fclose(in_file);
    fclose(out_file);
    return 0;
}

/*!
 * \brief Главная функция программы, обрабатывает аргументы командной строки и выполняет шифрование или расшифровку.
 *
 * \param argc Количество аргументов командной строки.
 * \param argv Массив строк аргументов командной строки.
 * \return Возвращает 0 при успешном выполнении, иначе 1.
 */
int main(int argc, char *argv[]) {
    int opt;
    int encrypt_flag = 0, decrypt_flag = 0;
    char *input_file = NULL, *output_file = NULL, *password = NULL;

    while ((opt = getopt(argc, argv, "edi:o:p:")) != -1) {
        switch (opt) {
            case 'e':
                encrypt_flag = 1;
                break;
            case 'd':
                decrypt_flag = 1;
                break;
            case 'i':
                input_file = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if ((encrypt_flag && decrypt_flag) || !input_file || !output_file || !password) {
        print_usage(argv[0]);
        return 1;
    }

    if (encrypt_flag) {
        return encrypt_file(input_file, output_file, password);
    } else if (decrypt_flag) {
        return decrypt_file(input_file, output_file, password);
    }

    print_usage(argv[0]);
    return 1;
}
