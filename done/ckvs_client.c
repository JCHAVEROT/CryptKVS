/**
 * @file ckvs_client.c
 * @brief c.f. ckvs_client.h
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <json-c/json.h>
#include "ckvs_rpc.h"
#include "ckvs_utils.h"
#include "ckvs_io.h"
#include "ckvs.h"
#include "util.h"
#include "ckvs_crypto.h"
#include "ckvs_local.h"

#include <openssl/hmac.h>


<<<<<<< HEAD

/*
 * To avoid circular dependencies.
 */
//struct json_object;

=======
#define FORMATGET(key, auth_key) "get?key=<" ##key ">&auth_key=<" ##auth_key ">"
#define STR(a) #a
>>>>>>> ebe01950cbf5556c1b149742625613e3c325ca62

// ----------------------------------------------------------------------
/**
 * @brief enum crypt_type with two modes decryption and encryption
 */
enum crypt_type {
    DECRYPTION,
    ENCRYPTION
};

int ckvs_client_stats(const char *url, int optargc, char **optargv) {
    if (optargc > 0) {
        //error
        return ERR_TOO_MANY_ARGUMENTS;
    }

    //check if the pointer is valid
    if (url == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //initialiaze the struct ckvs_connection
    ckvs_connection_t conn;

    //initialiaze the struct ckvs
    struct CKVS ckvs;
    memset(&ckvs, 0, sizeof(struct CKVS));


    //initialize the connection and check errors
    int err = ckvs_rpc_init(&conn, (const char *) url);
    if (err != ERR_NONE) {
        //error
        ckvs_rpc_close(&conn);
        return err;
    }

    //call the server
    err = ckvs_rpc(&conn, "stats");
    if (err != ERR_NONE) {
        //error
        ckvs_rpc_close(&conn);
        return err;
    }

    //parse into json object the downloaded content
    struct json_object *root_obj = json_tokener_parse(conn.resp_buf);
    if (root_obj == NULL) {
        //error
        pps_printf("%s\n", "An error occured when parsing the string into a json object");
        ckvs_rpc_close(&conn);
        return ERR_IO;
    }


    err = retrieve_ckvs_from_json(&ckvs, root_obj);
    if (err != ERR_NONE) {
        //error
        ckvs_rpc_close(&conn);
        json_object_put(root_obj);
        ckvs_close(&ckvs);
        return err;
    }

    //print the content downloaded from the server
    print_header(&(ckvs.header));

    //print the key of the entries
    for (size_t i = 0; i < ckvs.header.table_size; ++i) {
        if (strlen(ckvs.entries[i].key) != 0) {
            pps_printf("  %s             : " STR_LENGTH_FMT(CKVS_MAXKEYLEN) "\n", "Key", ckvs.entries[i].key);
        }
    }

    //free the struct JSON
    err = json_object_put(root_obj);
    if (err != 1) {
        //error
        ckvs_rpc_close(&conn);
        ckvs_close(&ckvs);
        return err;
    }

    //close the connection
    ckvs_rpc_close(&conn);

    //free pointers
    ckvs_close(&ckvs);

    return ERR_NONE;
}


int ckvs_client_get(const char *url, int optargc, char **optargv) {
    if (optargc < 2) return ERR_NOT_ENOUGH_ARGUMENTS;
    if (optargc > 2) return ERR_TOO_MANY_ARGUMENTS;

    const char *key = optargv[0];
    const char *pwd = optargv[1];

    //check if the pointeurs are valid
    if (key == NULL || pwd == NULL || url == NULL) {
        //error
        return ERR_INVALID_ARGUMENT;
    }

    //initialiaze the struct ckvs_connection
    ckvs_connection_t conn;

    //initialiaze the struct ckvs
    struct CKVS ckvs;
    memset(&ckvs, 0, sizeof(struct CKVS));


    //initialize the connection and check errors
    int err = ckvs_rpc_init(&conn, (const char *) url);
    if (err != ERR_NONE) {
        //error
        return err;
    }

    //initialize the struct ckvs_memrecord_t
    ckvs_memrecord_t ckvs_mem;
    memset(&ckvs_mem, 0, sizeof(ckvs_memrecord_t));

    //to generate in particular the auth_key and c1 and store them in ckvs_mem
    err = ckvs_client_encrypt_pwd(&ckvs_mem, key, pwd);
    if (err != ERR_NONE) {
        // error
        ckvs_rpc_close(&conn);
        ckvs_close(&ckvs);
        return err;
    }

<<<<<<< HEAD
    char *ready_key = NULL;
    CURL* curl=curl_easy_init();
    if (curl!=NULL) {
        ready_key = curl_easy_escape(curl, key, strlen(key));
        if (ready_key == NULL) {

            ckvs_rpc_close(&conn);
            curl_free(curl);
            return ERR_IO;
        }
        curl_easy_cleanup(curl);
    }else{
        ckvs_rpc_close(&conn);
        return ERR_IO;
=======
    //computed the url-escaped key
    char *ready_key = curl_easy_escape(conn.curl, key, strlen(key));
    if (ready_key == NULL) {
        //error
        ckvs_rpc_close(&conn);
        ckvs_close(&ckvs);
        return ERR_OUT_OF_MEMORY;
>>>>>>> ebe01950cbf5556c1b149742625613e3c325ca62
    }

    //print_SHA("",&ckvs_mem.auth_key);

    //compute the hex-encoded auth_key
    char buffer[SHA256_PRINTED_STRLEN];
    SHA256_to_string(&(ckvs_mem.auth_key), buffer);

<<<<<<< HEAD
    char *page = calloc(SHA256_PRINTED_STRLEN+ strlen(ready_key) + 19, sizeof(char));
=======
    char *page = calloc(SHA256_PRINTED_STRLEN + strlen(ready_key) + 19, sizeof(char));
>>>>>>> ebe01950cbf5556c1b149742625613e3c325ca62
    if (page == NULL) {
        //error
        curl_free(ready_key);
        ckvs_rpc_close(&conn);
        ckvs_close(&ckvs);
        return ERR_OUT_OF_MEMORY;
    }
    strcpy(page, "get?key=");
<<<<<<< HEAD
    strcat(page, ready_key);
    strcat(page, "&auth_key=");
    strncat(page, &buffer, SHA256_PRINTED_STRLEN);
=======
    strncat(page, ready_key, strlen(ready_key));
    strcat(page, "&auth_key=");
    strncat(page, buffer, SHA256_PRINTED_STRLEN);
>>>>>>> ebe01950cbf5556c1b149742625613e3c325ca62

    //pps_printf("%s\n", page);

    //free curl
    curl_free(ready_key);

    //call the server
    err = ckvs_rpc(&conn, page);
    if (err != ERR_NONE) {
        //error
        ckvs_rpc_close(&conn);
        ckvs_close(&ckvs);
        return err;
    }
    pps_printf("%s\n", conn.resp_buf);
    //free pointer
    free(page); page = NULL;

    //parse into json object the downloaded content
    struct json_object *root_obj = json_tokener_parse(conn.resp_buf);
    if (root_obj == NULL) {
        //error
        pps_printf("%s\n", "An error occured when parsing the string into a json object");
        ckvs_rpc_close(&conn);
        ckvs_close(&ckvs);
        return ERR_IO;
    }

<<<<<<< HEAD
    char* c2_str[SHA256_PRINTED_STRLEN+1];
    ckvs_sha_t* c2= calloc(1, sizeof(ckvs_sha_t));
    //get_string(conn.resp_buf,"c2",c2);
    //pps_printf("%s\n",c2);

    struct json_object *root_obj = json_tokener_parse(conn.resp_buf);
    if (root_obj == NULL) {
        //error
        pps_printf("%s\n", "An error occured when parsing the string into a json object");
        ckvs_rpc_close(&conn);
        free(c2);
        return ERR_IO;
    }
    err=get_string(root_obj,"c2",c2_str);
    if (err!=ERR_NONE){
        ckvs_rpc_close(&conn);
        free(c2);
        json_object_put(root_obj);
        return err;
    }
    //pps_printf("%s \n",c2_str);
    err= SHA256_from_string(c2_str, c2);
    if (err!=ERR_NONE){
        ckvs_rpc_close(&conn);
        free(c2);
        json_object_put(root_obj);
        return err;
    }


    unsigned char* data=calloc(conn.resp_size , sizeof(unsigned char));
    if (data==NULL){
        ckvs_rpc_close(&conn);
        free(c2);
        json_object_put(root_obj);
        return ERR_OUT_OF_MEMORY;
    }

    err=get_string(root_obj,"data",data);
    if (err!=ERR_NONE){
        free(data);
        ckvs_rpc_close(&conn);
        free(c2);
        json_object_put(root_obj);
        return err;
=======
    //the string for c2 retrieved from the json object
    char c2_buf[SHA256_PRINTED_STRLEN];
    err = get_string(root_obj, "c2", c2_buf);
    if (err != ERR_NONE) {
        //error
        ckvs_rpc_close(&conn);
        ckvs_close(&ckvs);
        return  err;
>>>>>>> ebe01950cbf5556c1b149742625613e3c325ca62
    }

    //compute the SHA256 of c2 from the string
    ckvs_sha_t c2;
    err = SHA256_from_string((const char *) c2_buf, &c2);
    if (err == -1) {
        //error
        ckvs_rpc_close(&conn);
        ckvs_close(&ckvs);
        return ERR_IO; //TODO à verifier si c'est bien err_io
    }

    //now we have c2, compute the masterkey
    err = ckvs_client_compute_masterkey(&ckvs_mem, &c2);
    if (err != ERR_NONE) {
        // Error
        ckvs_rpc_close(&conn);
        ckvs_close(&ckvs);
        return err;
    }

    //buffer to store the hex-encoded string for data retrieved from the json object
    char* buf_encrypted=calloc(10000, sizeof(char*)); //TODO change count
    char* buf_decrypted=calloc(10000, sizeof(char*));
    err = get_string(root_obj, "data", buf_encrypted);
    if (err != ERR_NONE) {
        //error
        ckvs_rpc_close(&conn);
        ckvs_close(&ckvs);
        return err;
    }
    hex_decode(buf_encrypted, buf_decrypted);
    pps_printf("%s", buf_decrypted);

    err = ckvs_client_compute_masterkey(&ckvs_mem, c2);
    if (err != ERR_NONE) {
        // Error
        free(data);
        free(c2);
        ckvs_close(&ckvs);
        json_object_put(root_obj);
        return err;
    }


    data=realloc(data, strlen(data)+1);

    //initialize the string where the decrypted secret will be stored
    size_t decrypted_len = strlen(data) + EVP_MAX_BLOCK_LENGTH;
    unsigned char *decrypted = calloc(decrypted_len, sizeof(unsigned char));

    if (decrypted == NULL) {
        free(data);
        free(c2);
        ckvs_close(&ckvs);
        json_object_put(root_obj);
        return ERR_OUT_OF_MEMORY;
    }

    //
    uint8_t data_uint= calloc();
     hex_decode(data,data_uint);


    //decrypts the string with the secret with in particular the master_key stored in ckvs_mem
    err = ckvs_client_crypt_value(&ckvs_mem, DECRYPTION, data, strlen(data), decrypted,
                                  &decrypted_len);

    if (err != ERR_NONE) {
        // Error
        /*print_SHA("auth :",&ckvs_mem.auth_key);
        print_SHA("master :",&ckvs_mem.master_key);
        print_SHA("streched :",&ckvs_mem.stretched_key);
        print_SHA("c1 :",&ckvs_mem.c1);
        pps_printf("%d , %s \n ", strlen(data),data);*/
        //pps_printf("%d",decrypted_len);

        //print_SHA("c2",c2);


        pps_printf(" \n");
        free(data);
        free(c2);
        curl_free(ready_key);
        ckvs_close(&ckvs);
        free_uc(&decrypted);
        ckvs_rpc_close(&conn);

        return err;
    }

    //check if we have to end the lecture
    for (size_t i = 0; i < decrypted_len; ++i) {
        if ((iscntrl(decrypted[i]) && decrypted[i] != '\n')) break;
        pps_printf("%c", decrypted[i]);
    }





<<<<<<< HEAD
    free(c2);
    free(data);
    json_object_put(root_obj);
    curl_free(ready_key);
    free_uc(&decrypted);
=======
    //free elements
>>>>>>> ebe01950cbf5556c1b149742625613e3c325ca62
    ckvs_rpc_close(&conn);
    ckvs_close(&ckvs);

    return ERR_NONE;

}

/* *************************************************** *
 * TODO WEEK 13                                        *
 * *************************************************** */
int ckvs_client_set(const char *url, int optargc, char **optargv) {
    return NOT_IMPLEMENTED;
}

int ckvs_client_new(const char *url, int optargc, char **optargv) {
    return NOT_IMPLEMENTED;
}
