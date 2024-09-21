/**
 *
 * @author Roman Machala
 * @date 21.09.2024
 *
 *   
 */ 

#include <stdbool.h>


/**
 *
 * @brief struktura reprezentujici argumenty prikazove radky
 * 
 */
typedef struct arguments{
    char *host;                         /* IP adresa nebo domena hosta */
    unsigned int port;                  /* cislo portu hosta */
    unsigned int active_timeout;        /* aktivni timeout v sec */
    unsigned int inactive_timeout;      /* inaktivni timeout v sec */
    char *file_path;                    /* cesta k souboru obsahujici PCAP zaznamy */
    bool debug;                         /* flag udavajici DEBUG mod */
} arguments;

/**
 * 
 * @brief funkce zpracovavajici parametry prikazove radky
 * 
 * @param args struktura pro uchovani zpracovanych parametru
 * @param arg parametry prikazove radky jako retezce
 * @param argc pocet vlozenych parametru
 * 
 * @returns true v pripade spravneho zpracovani jinak false
 * 
 */
bool parse_arguments(arguments *args, char *arg[], int argc); 

/**
 * 
 * @brief funkce kontrolujici spravnost zadanych argumentu a prevadejici je na jejich pozadovany format
 * 
 * @param args struktura obsahujici argumenty
 * 
 * @returns navratovy kod odpovidajici spravnemu zpracovani nebo specificke chybe
 *  
 */
int check_arguments(arguments *args);

bool next_argument(int next_pos, int argc, char *arg[]);

int get_type_param(char *param);

bool get_host_and_port(char *param, arguments *args);

void print_error(int code);