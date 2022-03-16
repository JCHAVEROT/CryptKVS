/**
 * @file ckvs_local.c
 * @brief
 *
 * @author A. Troussard
 */


/**
 * @brief Opens the CKVS database at the given filename and executes the 'stats' command,
 * ie. prints information about the database.
 * DO NOT FORGET TO USE pps_printf to print the header/entries!!!
 *
 * @param filename (const char*) the path to the CKVS database to open
 * @return int, an error code
 */
int ckvs_local_stats(const char *filename){
    FILE* file=NULL;
    file= fopen(filename,"rb");
    if (file==NULL){
        return ERR_IO;
    }
    char *header_str="\0";
    size_t nb_ok = fread(header_str, sizeof(char), CKVS_HEADERSTRINGLEN, file);
    if (nb_ok != CKVS_HEADERSTRINGLEN) {
        fclose(file);
        return ERR_IO;
    }

    uint32_t infos[CKVS_UINT32_T_ELEMENTS]= {0};
    size_t nb_ok = fread(infos, sizeof(uint32_t), 4, file);
    if (nb_ok != CKVS_UINT32_T_ELEMENTS) {
        fclose(file);
        return ERR_IO;
    }
    fclose(file);



    if(strncmp(CKVS_HEADERSTRING_PREFIX,header_str,strlen(CKVS_HEADERSTRING_PREFIX))!=0){
        return ERR_CORRUPT_STORE;
    }

    if (infos[0]!=1){
        return ERR_CORRUPT_STORE;
    }
    uint32_t table_size= infos[1];
    while (table_size>=2){
        if (table_size%2!=0) break;
        table_size=table_size/2;
    }
    if (table_size!=1) return ERR_CORRUPT_STORE;

    struct ckvs_header* header= {
            header_str,infos[0],infos[1],infos[2],infos[3];
    };
    print_header(header);










}

