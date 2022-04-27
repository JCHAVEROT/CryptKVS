/*
 * cryptkvs -- main ; argument parsing and dispatch ; etc.
 */

#include <stdio.h>
#include "error.h"
#include "ckvs_local.h"
#include "ckvs_utils.h"


//type for a command
typedef int ckvs_command(const char* filename, int optargc, char* optargv[]);

typedef struct{
    const char* name;
    const char* description;
    ckvs_command* command;
} ckvs_command_mapping;

const ckvs_command_mapping commands[]={{"stats","- cryptkvs <database> stats\n",&ckvs_local_stats } ,
                                 {"get","- cryptkvs <database> get <key> <password>\n",&ckvs_local_get },
                                 {"set","- cryptkvs <database> set <key> <password> <filename>\n",&ckvs_local_set },
                                 {"new","- cryptkvs <database> new <key> <password>\n",&ckvs_local_new }
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
        for (size_t i = 0; i < sizeof(commands)/ sizeof(ckvs_command_mapping); ++i) {
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



    if (argc < 3) return ERR_INVALID_COMMAND;

    const char *db_filename = argv[1];
    const char *cmd = argv[2];

    int optargc = argc - 3;
    char** optargv = argv + 3;
    for (size_t i = 0; i < sizeof(commands)/ sizeof(ckvs_command_mapping); ++i) {
        ckvs_command_mapping c=commands[i];
        if (strcmp(cmd, c.name) == 0) {
            return c.command(db_filename,optargc,optargv);
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
