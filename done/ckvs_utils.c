//
// Created by trous on 15.03.2022.
//

#include <stdio.h>
#include "ckvs_utils.h"
#include "ckvs.h"
#include <inttypes.h>



void print_header(const struct ckvs_header* header){
    printf("CKVS Header type       : %s\n",header->header_string);
    printf("CKVS Header version    : %" PRIu32 "\n", header->version);
    printf("CKVS Header table_size : %" PRIu32 "\n", header->table_size);
    printf("CKVS Header threshold  : %" PRIu32 "\n", header->threshold_entries);
    printf("CKVS Header num_entries: %" PRIu32 "\n", header->num_entries);
    return;
}

void print_entry(const struct ckvs_entry* entry){
    printf("    Key   : %s\n",entry->key);
    printf("    Value : off %" PRIu64 " len %" PRIu64 "\n", entry->value_off,entry->value_len);
    printf("    Auth  : ");
    print_SHA("    Auth  : ",&entry->auth_key);
    print_SHA("    C2    : %",&entry->c2);
    return;
}





void print_SHA(const char *prefix, const struct ckvs_sha *sha) {
    char buffer[SHA256_PRINTED_STRLEN] = {0};
    SHA256_to_string(sha, buffer);
    pps_printf("%-5s: %s\n", prefix, buffer);
}

void SHA256_to_string(const struct ckvs_sha *sha, char *buf) {
    hex_encode(sha->sha, SHA256_DIGEST_LENGTH, buf);
}

void hex_encode(const uint8_t *in, size_t len, char *buf) {
    for (size_t i = 0; i < len; ++i) {
        sprintf(&buf[i], "%02x",  in[i]);
    }
}




