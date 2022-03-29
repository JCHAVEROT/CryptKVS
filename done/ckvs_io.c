/**
 * @file ckvs_io.c
 * @brief c.f. ckvs_io.h
 *
 * @author A.Troussard, J.Chaverot
 */
#include <stdio.h>
#include <string.h>
#include "ckvs_utils.h"
#include "ckvs.h"
#include "error.h"
#include <stdint.h>
#include <stdbool.h>
#include "ckvs_io.h"
// ----------------------------------------------------------------------
int ckvs_open(const char *filename, struct CKVS *ckvs) {
    //check pointers
    if (ckvs==NULL||filename == NULL) return ERR_INVALID_ARGUMENT;
    //initialize the CKVS database
    memset(ckvs,0, sizeof(struct CKVS));

    //open the file in read binary mode and assign it to the CKVS File
    FILE *file = NULL;
    file = fopen(filename, "r+b");
    if (file == NULL) {
        //error
        return ERR_IO;
    }
    ckvs->file=file;

    //read the header and that it was well read
    char header_str[CKVS_HEADERSTRINGLEN];
    size_t nb_ok = fread(header_str, sizeof(char), CKVS_HEADERSTRINGLEN, file);
    if (nb_ok != CKVS_HEADERSTRINGLEN) {
        //error
        fclose(file);
        return ERR_IO;
    }
    //read the infos and that they were well read
    uint32_t infos[CKVS_UINT32_T_ELEMENTS]= {0};
    size_t nb_ok2 = fread(infos, sizeof(uint32_t), 4, file);
    if (nb_ok2 != CKVS_UINT32_T_ELEMENTS) {
        //error
        fclose(file);
        return ERR_IO;
    }

    if (strncmp(CKVS_HEADERSTRING_PREFIX,header_str,strlen(CKVS_HEADERSTRING_PREFIX)) != 0) {
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
        if (table_size%2 != 0) break;
        table_size=table_size/2;
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

    strcpy(header.header_string,header_str);
    ckvs->header= header;

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
void ckvs_close(struct CKVS *ckvs){
    //check if the argument is valid, if so exit the function without doing anything
    if (ckvs == NULL) return ;
    //close to file of the CKVS and make it point to NULL
    if (ckvs->file != NULL) fclose(ckvs->file);
    ckvs->file=NULL;
}
// ----------------------------------------------------------------------
int ckvs_find_entry(struct CKVS *ckvs, const char *key, const struct ckvs_sha *auth_key, struct ckvs_entry **e_out){
    //check pointeurs
    if (ckvs == NULL || key == NULL || auth_key == NULL || e_out == NULL) return ERR_INVALID_ARGUMENT;

    //booleans created to follow if the key was found in the CKVS database, and if found, check if the auth_key is correct
    bool keyWasFound = false;
    bool authKeyIsCorrect = false;

    //iterate in the array
    for (size_t i = 0 ; i < CKVS_FIXEDSIZE_TABLE ; ++i) {
        //pps_printf("-------------\n %s \n---------------\n",ckvs->entries[i].key);
        if (strncmp(ckvs->entries[i].key, key,CKVS_MAXKEYLEN) == 0) {
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

int read_value_file_content(const char* filename, char** buffer_ptr, size_t* buffer_size){
    CKVS_t ckvs;
    memset(&ckvs,0, sizeof(struct CKVS));
    ckvs_open(filename,&ckvs);
    fseek(ckvs.file, 0, SEEK_END);
    size_t size = ftell(ckvs.file) ;
    *buffer_ptr=calloc(size, sizeof(char));
    
    return ERR_NONE;

}


