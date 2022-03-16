//
// Created by trous on 15.03.2022.
//

void print_SHA(const char *prefix, const struct ckvs_sha *sha) {
    char buffer[SHA256_PRINTED_STRLEN];
    SHA256_to_string(sha, buffer);
    pps_printf("%-5s: %s\n", prefix, buffer);
}


void SHA256_to_string(const struct ckvs_sha *sha, char *buf) {
    hex_encode(sha.sha, SHA256_DIGEST_LENGTH, buf);
}

void hex_encode(const uint8_t *in, size_t len, char *buf) {
    for (size_t i = 0; i < len; ++i) {
        sprintf(buf, "%02x", in));
    }
}

