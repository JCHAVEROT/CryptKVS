/**
 * @file unit-test-ios.c
 * @brief Unit tests for the ckvs_io functions
 *
 * @author A. Clergeot, EPFL
 * @date 2021
 */

#ifdef WITH_RANDOM
// for thread-safe randomization (useless here, but kept in case we'd like to have random generation inside the tests)
#include <time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#endif

#include <check.h>
#include <inttypes.h>

#include "tests.h"
#include "error.h"
#include "ckvs.h"
#include "ckvs_io.h"

#include "ckvs_test_util.h"

IMPLEMENT_MUTED_PPS_PRINTF


// ======================================================================
START_TEST(CKVS_struct_offsets)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // In the struct CKVS, please respect the order : header, entries, file
    ck_assert_int_eq(offsetof(struct CKVS, header), 0);
    ck_assert_int_eq(offsetof(struct CKVS, entries), sizeof(struct ckvs_header));
    // ckvs.entries should be an array
    ck_assert_int_eq(offsetof(struct CKVS, file), sizeof(struct ckvs_header) + sizeof(struct ckvs_entry) * CKVS_FIXEDSIZE_TABLE);
    ck_assert_int_eq(sizeof(struct CKVS), sizeof(struct ckvs_header) + sizeof(struct ckvs_entry) * CKVS_FIXEDSIZE_TABLE + sizeof(FILE*));

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(open_null_arguments)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    struct CKVS ckvs;
    ck_assert_int_eq(ckvs_open(NULL, &ckvs), ERR_INVALID_ARGUMENT);
    ck_assert_int_eq(ckvs_open(NON_EXISTING_CKVS, NULL), ERR_INVALID_ARGUMENT);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(open_non_existing_file)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    struct CKVS ckvs;
    ck_assert_int_eq(ckvs_open(NON_EXISTING_CKVS, &ckvs), ERR_IO);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST


// ======================================================================
START_TEST(open_invalid_header_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    init_header(header, "CS212 Crypt", 1, 64, 10, 0); // invalid header_str
    ckvs_entry_t* entries = calloc(header.table_size, sizeof(ckvs_entry_t));
    ck_assert_ptr_nonnull(entries);
    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &header, entries), 0);
    free(entries);


    struct CKVS ckvs;
    ck_assert_int_eq(ckvs_open(DUMMY_NAME, &ckvs), ERR_CORRUPT_STORE);

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(open_invalid_header_2)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    init_header(header, "CS212 CryptKVS", 2, 64, 16, 0); // version != 1
    ckvs_entry_t* entries = calloc(header.table_size, sizeof(ckvs_entry_t));
    ck_assert_ptr_nonnull(entries);
    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &header, entries), 0);
    free(entries);


    struct CKVS ckvs;
    ck_assert_int_eq(ckvs_open(DUMMY_NAME, &ckvs), ERR_CORRUPT_STORE);

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(open_invalid_header_3)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    init_header(header, "CS212 CryptKVS", 1, 66, 10, 0); // not a power of 2 (and != 64 for weeks < 8)
    ckvs_entry_t* entries = calloc(header.table_size, sizeof(ckvs_entry_t));
    ck_assert_ptr_nonnull(entries);
    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &header, entries), 0);
    free(entries);

    struct CKVS ckvs;
    ck_assert_int_eq(ckvs_open(DUMMY_NAME, &ckvs), ERR_CORRUPT_STORE);

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(open_invalid_header_4)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    init_header(header, "CS212 CryptKVS", 1, 64, 10, 0);

    FILE* f = fopen(DUMMY_NAME, "wb");
    ck_assert_ptr_nonnull(f);
    ck_assert_int_eq(fwrite(&header, sizeof(ckvs_header_t) / 2, 1, f), 1); // write half the header only
    fclose(f);

    struct CKVS ckvs;
    ck_assert_int_eq(ckvs_open(DUMMY_NAME, &ckvs), ERR_IO);

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(open_invalid_header_5)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    init_header(header, "CS212 CryptKVS", 1, 64, 10, 0);

    ckvs_entry_t* entries = calloc(63, sizeof(ckvs_entry_t)); // do not write enough entries
    ck_assert_ptr_nonnull(entries);

    FILE* f = fopen(DUMMY_NAME, "wb");
    ck_assert_ptr_nonnull(f);

    ck_assert_int_eq(fwrite(&header, sizeof(ckvs_header_t), 1, f), 1);
    ck_assert_int_eq(fwrite(entries, sizeof(ckvs_entry_t), 63, f), 63);
    fclose(f);
    free(entries);

    struct CKVS ckvs;
    ck_assert_int_eq(ckvs_open(DUMMY_NAME, &ckvs), ERR_IO);

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(open_valid_header_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    init_header(h, "CS212 CryptKVS001", 1, 64, 10, 1);

    ckvs_entry_t* entries = calloc(h.table_size, sizeof(ckvs_entry_t));
    ck_assert_ptr_nonnull(entries);
    strcpy(entries[h.table_size / 2].key, "Test key");
    strcpy((char*) entries[h.table_size / 2].auth_key.sha, "hello world");
    strcpy((char*) entries[h.table_size / 2].c2.sha, "foo bar baz qux");
    entries[h.table_size / 2].value_off = 1235;
    entries[h.table_size / 2].value_len = 81321;

    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &h, entries), 0);

    struct CKVS ckvs;
    ck_assert_int_eq(ckvs_open(DUMMY_NAME, &ckvs), ERR_NONE);

    // header & entries should be the same
    ck_assert_int_eq(memcmp(&ckvs.header, &h, sizeof(ckvs_header_t)), 0);
    ck_assert_int_eq(memcmp(ckvs.entries, entries, h.table_size * sizeof(ckvs_entry_t)), 0);
    // file should stay open and not null:
    ck_assert_ptr_nonnull(ckvs.file); 
    ck_assert_int_ne(ftell(ckvs.file), -1);

    free(entries);
    ckvs_close(&ckvs);

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(close_NULL_file)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    struct CKVS ckvs;
    ckvs.file = NULL;

    // should not segfault
    ckvs_close(NULL);
    ckvs_close(&ckvs);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(close_open_file)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    init_header(h, "CS212 CryptKVS001", 1, 64, 10, 0);

    ckvs_entry_t* entries = calloc(h.table_size, sizeof(ckvs_entry_t));
    ck_assert_ptr_nonnull(entries);

    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &h, entries), 0);
    free(entries);

    struct CKVS ckvs;
    ck_assert_int_eq(ckvs_open(DUMMY_NAME, &ckvs), ERR_NONE);


    ckvs_close(&ckvs);
    ck_assert_ptr_null(ckvs.file);

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST



// ======================================================================
Suite* ios_test_suite()
{
#ifdef WITH_RANDOM
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
    srand(time(NULL) ^ getpid() ^ pthread_self());
#pragma GCC diagnostic pop
#endif // WITH_RANDOM
    
    Suite* s = suite_create("Tests for IO operations (may not be exhaustive!)");

    Add_Case(s, tc1, "IOs tests");
    tcase_add_test(tc1, CKVS_struct_offsets);
    tcase_add_test(tc1, open_null_arguments);
    tcase_add_test(tc1, open_non_existing_file);
    tcase_add_test(tc1, open_invalid_header_1);
    tcase_add_test(tc1, open_invalid_header_2);
    tcase_add_test(tc1, open_invalid_header_3);
    tcase_add_test(tc1, open_invalid_header_4);
    tcase_add_test(tc1, open_invalid_header_5);
    tcase_add_test(tc1, open_valid_header_1);
    tcase_add_test(tc1, close_NULL_file);
    tcase_add_test(tc1, close_open_file);

    return s;
}

TEST_SUITE(ios_test_suite)
