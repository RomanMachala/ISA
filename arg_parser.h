#ifndef ARG_PARSER_H
#define ARG_PARSER_H

/**
 *
 * @author Roman Machala (xmacha86)
 * @date 21.09.2024
 *
 * @brief hlavickovy soubor pro logiku zpracovani vstupnich parametru programu
 *   
 */ 

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/**
 *
 * @brief struktura reprezentujici argumenty prikazove radky
 * 
 */
typedef struct arguments{
    char *host;                         /* IP adresa nebo domena hosta */
    int port;                           /* cislo portu hosta */
    unsigned int active_timeout;        /* aktivni timeout v sec */
    unsigned int inactive_timeout;      /* inaktivni timeout v sec */
    char *file_path;                    /* cesta k souboru obsahujici PCAP zaznamy */
    bool debug;                         /* flag udavajici DEBUG mod */
    char *address_hostname;             /* Adresa kolektoru */
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

/**
 * 
 * @brief pomocna funkce pro kontrolu nasledujiciho parametru, zdali existuje a ma spravny format (pro prepinace -i, -a)
 * 
 * @param next_pos index nasledujiciho parametru
 * @param argc celkovy pocet parametru
 * @param arg vstupni parametry
 * 
 * @returns true v pripade spravneho parametru jinak false
 * 
 */
bool next_argument(int next_pos, int argc, char *arg[]);

/**
 * 
 * @brief pomocna funkce pro ziskani o jaky typ parametru se jedna (prepinace -a|-i, host:port, ...) 
 * 
 * @param param aktualne zpracovavany parametr
 * 
 * @returns navratovy kod odpovidajici typu parametru
 * 
 */
int get_type_param(char *param);

/**
 * 
 * @brief funkce extrahujici HOST a PORT ze retezce, zaroven kontroluje jejich spravnost
 * 
 * @param param zpracovavany retezec
 * @param args struktura obsahujici extrahovane parametry
 * 
 * @returns true v pripade spravneho zpracovani jinak false 
 * 
 */
bool get_host_and_port(char *param, arguments *args);

/**
 * 
 * @brief pomocna funkce pro vypis na stderr pri spatne kombinaci parametru, chybne zadane hodnoty, chybejici hodnoty, ...
 * 
 * @param code kod odpovidajici specificke chybe
 *  
 */
void print_error(int code);

/**
 *
 * @brief pomocna funkce pro debugovani, vypisuje pouzite parametry a jejich hodnoty 
 * 
 * @param args struktura obsahujici parametry
 * 
 */
void print_params(arguments *args);

/**
 * 
 * @brief funkce prevadejici domenu na ip adresu
 * 
 * @param hostname domena
 * 
 * @returns ip adresu ve formatu retezce
 * 
 */
char *get_address_hostname(char *hostname);

#endif