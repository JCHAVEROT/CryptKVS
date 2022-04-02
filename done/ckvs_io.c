/**
 * @file ckvs_io.c
 * @brief c.f. ckvs_io.h
 */
#include <stdio.h>
#include <string.h>
#include "ckvs_utils.h"
#include "ckvs.h"
#include "error.h"
#include <stdint.h>
#include <stdbool.h>
#include "ckvs_io.h"
#include <stdlib.h>
// ----------------------------------------------------------------------
int ckvs_open(const char *filename, struct CKVS *ckvs) {
    //check pointers
    if (ckvs == NULL || filename == NULL) return ERR_INVALID_ARGUMENT;
    //initialize the CKVS database
    memset(ckvs, 0, sizeof(struct CKVS));

    //open the file in read binary mode and assign it to the CKVS File
    FILE *file = NULL;
    file = fopen(filename, "r+b");
    if (file == NULL) {
        //error
        pps_printf("open");
        return ERR_IO;
    }
    ckvs->file = file;

    //read the header and that it was well read
    char header_str[CKVS_HEADERSTRINGLEN];
    size_t nb_ok = fread(header_str, sizeof(char), CKVS_HEADERSTRINGLEN, file);
    if (nb_ok != CKVS_HEADERSTRINGLEN) {
        //error
        fclose(file);
        return ERR_IO;
    }
    //read the infos and that they were well read
    uint32_t infos[CKVS_UINT32_T_ELEMENTS] = {0};
    size_t nb_ok2 = fread(infos, sizeof(uint32_t), 4, file);
    if (nb_ok2 != CKVS_UINT32_T_ELEMENTS) {
        //error
        fclose(file);
        return ERR_IO;
    }

    if (strncmp(CKVS_HEADERSTRING_PREFIX, header_str, strlen(CKVS_HEADERSTRING_PREFIX)) != 0) {
        //error
        fclose(file);
        return ERR_CORRUPT_STORE;
    }

    if (infos[0] != 1) {
        //error
        fclose(file);
        return ERR_CORRUPT_STORE;
    }
    uint32_t table_size = infos[1];
    while (table_size >= 2) {
        if (table_size % 2 != 0) break;
        table_size = table_size / 2;
    }
    if (table_size != 1) {
        //error
        fclose(file);
        return ERR_CORRUPT_STORE;
    }
    ckvs_header_t header = {
            .version           =infos[0],
            .table_size        =infos[1],
            .threshold_entries =infos[2],
            .num_entries       =infos[3]
    };

    strcpy(header.header_string, header_str);
    ckvs->header = header;

    if (ckvs->header.table_size != CKVS_FIXEDSIZE_TABLE) { //For now but to be deleted later
        fclose(file);
        return ERR_CORRUPT_STORE;
    }

    size_t nb_ok3 = fread(ckvs->entries, sizeof(ckvs_entry_t), CKVS_FIXEDSIZE_TABLE, file);
    if (nb_ok3 != CKVS_FIXEDSIZE_TABLE) {
        fclose(file);
        return ERR_IO;
    }

    return ERR_NONE;
}
// ----------------------------------------------------------------------
void ckvs_close(struct CKVS *ckvs) {
    //check if the argument is valid, if so exit the function without doing anything
    if (ckvs == NULL) return;
    //close to file of the CKVS and make it point to NULL
    if (ckvs->file != NULL) fclose(ckvs->file);
    ckvs->file = NULL;
}
// ----------------------------------------------------------------------
int ckvs_find_entry(struct CKVS *ckvs, const char *key, const struct ckvs_sha *auth_key, struct ckvs_entry **e_out) {
    //check pointeurs
    if (ckvs == NULL || key == NULL || auth_key == NULL || e_out == NULL) return ERR_INVALID_ARGUMENT;

    //booleans created to follow if the key was found in the CKVS database, and if found, check if the auth_key is correct
    bool keyWasFound = false;
    bool authKeyIsCorrect = false;

    //iterate in the array
    for (size_t i = 0; i < CKVS_FIXEDSIZE_TABLE; ++i) {
        //pps_printf("-------------\n %s \n---------------\n",ckvs->entries[i].key);
        if (strncmp(ckvs->entries[i].key, key, CKVS_MAXKEYLEN) == 0) {
            keyWasFound = true;
            if (ckvs_cmp_sha(&ckvs->entries[i].auth_key, auth_key) == 0) {
                authKeyIsCorrect = true;
                *e_out = &ckvs->entries[i];
            }
            break;
        }
    }

    if (!keyWasFound) {
        // Error
        return ERR_KEY_NOT_FOUND;
    }
    if (!authKeyIsCorrect) {
        // Error
        return ERR_DUPLICATE_ID;
    }

    return ERR_NONE;
}
// ----------------------------------------------------------------------
int read_value_file_content(const char *filename, char **buffer_ptr, size_t *buffer_size) {
    //check pointers
    if (filename == NULL || buffer_ptr == NULL || buffer_size == NULL) return ERR_INVALID_ARGUMENT;

    //creates and opens file
    FILE* file = NULL;
    file = fopen(filename, "rb"); //open in read binary mode
    if (file == NULL) {
        //error
        return ERR_IO;
    }
    //places the pointer at the end of the file
    int err = fseek(file, 0, SEEK_END);
    //check errors
    if (err != ERR_NONE) return err;
    //affects the string's length
    size_t size = (size_t) ftell(file);

    //places the pointer at the beginning of the file back
    fseek(file, 0, SEEK_SET);
    //creates a buffer and checks errors to put the read value
    *buffer_ptr = calloc(size + 1, sizeof(char)); //so the '\0' char fits
    if (*buffer_ptr==NULL) return ERR_INVALID_COMMAND;

    printf("size: %d \n",size);
    pps_printf("%s\n",*buffer_ptr);
    size_t nb = fread(*buffer_ptr, sizeof(char), size, file);
    pps_printf("%s\n",*buffer_ptr);
    pps_printf("nb : %d \n",nb);
    //check errors
    //printf("%s , size:%d\n",*buffer_ptr,size);
    if (nb!=size) return ERR_INVALID_COMMAND;
    *buffer_size = size + 1; //update the buffer size to have the place for the final '\0'
    (*buffer_ptr)[size] = '\0'; // to add the final '\0' //NOTE : est-ce qu'il n'est pas déjà à la fin de la string

    //closes the opened file and finishes
    fclose(file);
    return ERR_NONE;
}
// ----------------------------------------------------------------------
int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx) {
    //check ckvs pointer and validity of idx value
    if (ckvs == NULL || (idx < 0) || (idx >= CKVS_FIXEDSIZE_TABLE)) {
        return ERR_INVALID_ARGUMENT;
    }
    //place the pointer on the file on the right place and check errors
    int err = fseek(ckvs->file, idx * sizeof(struct ckvs_entry) + sizeof(ckvs_header_t), SEEK_SET);
    if (err != 0) {
        pps_printf("l");
        return ERR_IO;
    }

    //write the entry and check errors
    size_t nb2 = fwrite(&ckvs->entries[idx], sizeof(ckvs_entry_t),1,ckvs->file);
    if (nb2 != 1) {
        pps_printf("m");
        return ERR_IO;
    }
    return ERR_NONE;
}
// ----------------------------------------------------------------------
int ckvs_write_encrypted_value(struct CKVS *ckvs, struct ckvs_entry *e, const unsigned char *buf, uint64_t buflen) {

    //check pointers
    if (ckvs == NULL || e == NULL || buf == NULL) {
        return ERR_INVALID_ARGUMENT;
    }
    //to place the pointer at the end of the ckvs file
    int err = fseek(ckvs->file, 0, SEEK_END);
    if (err != ERR_NONE) {
        //error
        pps_printf("a");
        return err;
    }
    //to assign the new values of c2, value_off and value_len
    e->value_len = buflen;
    e->value_off = (size_t) ftell(ckvs->file);

    //write at the end of the ckvs file the encrypted value to writes
    err = fputs((const char *) buf , ckvs->file);
    if (err < 0) {//since fputs return a non-zero negative integer in case of success
        //error
        pps_printf("b");

        return err;
    }

    ckvs_entry_t out_entry; // a quoi sert out_entry??
    memset(&out_entry, 0, sizeof(out_entry));
    //free(buf); //to free the pointer //NOTE : à faire ici ?

    size_t idx=(size_t) (e - &ckvs->entries[0]);
    /*pps_printf("idx= %d \n",idx);
    for(size_t i =0;i< ckvs->header.table_size;i++){
        pps_printf("--------------------------");
        if (strlen(ckvs->entries[i].key) != 0){
            pps_printf("Entry %d : \n",i);
            print_entry(&ckvs->entries[i]);
        }
        pps_printf("--------------------------");

    }
    //pps_printf("++++++++++++++++++++++++");
    //print_entry(&ckvs->entries[idx]);*/


    //to modify the right entry in the ckvs table, index is obtained by substracting the pointers
    err = ckvs_write_entry_to_disk(ckvs,idx);
    if (err != ERR_NONE) {
        //error
        pps_printf("c");

        return err;
    }

    return ERR_NONE;
}



