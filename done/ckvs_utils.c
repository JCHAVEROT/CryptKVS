/**
 * @file ckvs_utils.c
 * @brief c.f. ckvs_utils.h
 *
 */
#include <stdio.h>
#include "ckvs_utils.h"
#include "ckvs.h"
#include "util.h"
#include <inttypes.h>
// ----------------------------------------------------------------------
void print_header(const struct ckvs_header* header){
    pps_printf("CKVS Header type       : %s\n",header->header_string);
    pps_printf("CKVS Header version    : %" PRIu32 "\n", header->version);
    pps_printf("CKVS Header table_size : %" PRIu32 "\n", header->table_size);
    pps_printf("CKVS Header threshold  : %" PRIu32 "\n", header->threshold_entries);
    pps_printf("CKVS Header num_entries: %" PRIu32 "\n", header->num_entries);
    return;
}
// ----------------------------------------------------------------------
void print_entry(const struct ckvs_entry* entry){
    pps_printf("    %s   : " STR_LENGTH_FMT(CKVS_MAXKEYLEN) "\n", "Key", entry->key);
    pps_printf("    Value : off %" PRIu64 " len %" PRIu64 "\n", entry->value_off,entry->value_len);
    print_SHA("    Auth  ",&entry->auth_key);
    print_SHA("    C2    ",&entry->c2);
    return;
}
// ----------------------------------------------------------------------
void print_SHA(const char *prefix, const struct ckvs_sha *sha) {
    if (prefix==NULL || sha==NULL) return;
    char buffer[SHA256_PRINTED_STRLEN];
    SHA256_to_string(sha, buffer);
    pps_printf("%-5s: %s\n", prefix, buffer);
    return;
}
// ----------------------------------------------------------------------
void hex_encode(const uint8_t *in, size_t len, char *buf) {
    if (in==NULL || buf==NULL) return;
    for (size_t i = 0; i < len; ++i) {
        sprintf(&buf[2*i], "%02x", in[i]);
    }
    return;
}
// ----------------------------------------------------------------------
void SHA256_to_string(const struct ckvs_sha *sha, char *buf) {
    if (sha==NULL || buf==NULL) return;
    hex_encode(sha->sha, SHA256_DIGEST_LENGTH, buf);
    return;
}
// ----------------------------------------------------------------------
int ckvs_cmp_sha(const struct ckvs_sha *a, const struct ckvs_sha *b) {
    return memcmp(a->sha, b->sha, SHA256_DIGEST_LENGTH);
}




