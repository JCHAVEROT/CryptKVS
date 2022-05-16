/*
 * cryptkvs -- main ; argument parsing and dispatch ; etc.
 */

#include <stdio.h>
#include "error.h"
#include "ckvs_local.h"
#include "ckvs_client.h"
#include "ckvs_httpd.h"
#include "ckvs_utils.h"


/**
 * @brief First prefix for an URL.
 */
#define URL_PREFIX_1 "https://"

/**
 * @brief Second prefix for an URL.
 */
#define URL_PREFIX_2 "http://"

//type for a command function
typedef int ckvs_command(const char *filename_or_url, int optargc, char *optargv[]);

//struct for a command mapping
typedef struct {
    const char *name;
    const char *description;
    ckvs_command *command_local;
    ckvs_command *command_remote;
} ckvs_command_mapping;

//list of commands
const ckvs_command_mapping commands[] = {{"stats", "- cryptkvs [<database>|<url>] stats\n",                           &ckvs_local_stats,      &ckvs_client_stats },
                                         {"get",   "- cryptkvs [<database>|<url>] get <key> <password>\n",            &ckvs_local_get,        &ckvs_client_get },
                                         {"set",   "- cryptkvs [<database>|<url>] set <key> <password> <filename>\n", &ckvs_local_set,        &ckvs_client_set },
                                         {"new",   "- cryptkvs [<database>|<url>] new <key> <password>\n",            &ckvs_local_new,        &ckvs_client_new },
                                         {"httpd", "- cryptkvs <database> httpd <url>\n",                             &ckvs_httpd_mainloop,   NULL }
};

/* *************************************************** *
 * TODO WEEK 09-11: Add then augment usage messages    *
 * *************************************************** */

/* *************************************************** *
 * TODO WEEK 04-07: add message                        *
 * TODO WEEK 09: Refactor usage()                      *
 * *************************************************** */
static void usage(const char *execname, int err) {
    if (err == ERR_INVALID_COMMAND) {
        pps_printf("Available commands:\n");
        for (size_t i = 0; i < sizeof(commands) / sizeof(ckvs_command_mapping); ++i) {
            pps_printf("%s", commands[i].description);
        }

    } else if (err >= 0 && err < ERR_NB_ERR) {
        pps_printf("%s exited with error: %s\n\n\n", execname, ERR_MESSAGES[err]);
    } else {
        pps_printf("%s exited with error: %d (out of range)\n\n\n", execname, err);
    }
}

/* *************************************************** *
 * TODO WEEK 04-11: Add more commands                  *
 * TODO WEEK 09: Refactor ckvs_local_*** commands      *
 * *************************************************** */
/**
 * @brief Runs the command requested by the user in the command line, or returns ERR_INVALID_COMMAND if the command is not found.
 *
 * @param argc (int) the number of arguments in the command line
 * @param argv (char*[]) the arguments of the command line, as passed to main()
 */
int ckvs_do_one_cmd(int argc, char *argv[]) {
    //check number of arguments
    if (argc < 3) return ERR_INVALID_COMMAND;

    const char *db_filename_or_url = argv[1];
    const char *cmd = argv[2];

    int optargc = argc - 3;
    char **optargv = argv + 3;

    //check if in local or with client, and then search for the right command and call it once found

    for (size_t i = 0; i < sizeof(commands) / sizeof(ckvs_command_mapping); ++i) {
        ckvs_command_mapping c = commands[i];
        if (strcmp(cmd, c.name) == 0) {
            return (strncmp(URL_PREFIX_1, db_filename_or_url, strlen(URL_PREFIX_1)) == 0 // start with https://
                || strncmp(URL_PREFIX_2, db_filename_or_url, strlen(URL_PREFIX_2)) == 0) // start with http://
                    ? c.command_remote(db_filename_or_url, optargc, optargv)
                    : c.command_local(db_filename_or_url, optargc, optargv);
        }
    }


    return ERR_INVALID_COMMAND;
}

#ifndef FUZZ

/**
 * @brief main function, runs the requested command and prints the resulting error if any.
 */
int main(int argc, char *argv[]) {
    int ret = ckvs_do_one_cmd(argc, argv);
    if (ret != ERR_NONE) {
        usage(argv[0], ret);
    }
    return ret;

}

#endif
