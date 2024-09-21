/**
 *
 * @author Roman Machala
 * @date 21.09.2024
 *
 *   
 */ 

#include "arg_parser.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

bool parse_arguments(arguments *args, char *arg[], int argc){
    
    /* Defaultni hodnoty pro timeout argumenty a pro debug mod*/
    args->active_timeout = 60;
    args->inactive_timeout = 60;
    args->debug = false;

    for (int i = 1; i < argc; i++){
        switch (get_type_param(arg[i]))
        {
        case 0: /* Odpovida zadanemu PCAP souboru */
            args->file_path = arg[i]; 
            break;
        case 1: /* Odpovida argumentu -a | --active */
            if(!next_argument(i + 1, argc, arg)){
                print_error(1);
                return false;
            }
            args->active_timeout = atoi(arg[i + 1]);
            i++; /* je treba dodatecne zvysit */
            break;
        case 2:
            if(!next_argument(i + 1, argc, arg)){
                print_error(2);
                return false;
            }
            args->inactive_timeout = atoi(arg[i + 1]);
            i++;
            break;
        case 3:
            if(!get_host_and_port(arg[i], args)){
                print_error(3);
                return false;
            }
            break;
        }
        

    }


    return true;
}

/**
 * 
 * @brief pomocna funkce nacteni dalsiho argumentu pro prepinace -i a -a
 * 
 * @param next_pos pozice v poli retezcu nasledujiciho argumentu
 * @param argc celkovy pocet zadanych argumentu
 */
bool next_argument(int next_pos, int argc, char *arg[]){
    if (next_pos >= argc) return false; /* pokud neni dalsi parametr neni treba pokracovat v kontrole */
    const char *param = arg[next_pos];

    /* Zkontroluje ze vsechny znaky jsou cisla */
    while(*param){
        if(!isdigit((unsigned char)*param)){
            return false;   /* v pripade ze nektery znak neni cislo vraci false */
        }
        param++;
    }

    return true;
}

/**
 *
 * @brief jednoducha funkce vracejici integer na zaklade o jaky parametr se jedna 
 * 
 * @param param aktualne zpracovavany parametr
 * 
 * @returns vraci cislo udavajici typ parametru
 * 
 */
int get_type_param(char *param){
    /**
     * 
     *  0 - cesta k PCAP souboru
     *  1 - prenipac -a | --active 
     *  2 - prepinac -i | --inactive
     *  3 - host:port       dle zadani se predpoklada ze je zadano jako [domena|IP]:port
     */
    if(strcmp(param, "-a") == 0 || strcmp(param, "--active") == 0){
        return 1;
    }else if(strcmp(param, "-i") == 0 || strcmp(param, "--inactive") == 0){
        return 2;
    }else if(strstr(":", param)){
        return 3;
    }else return 0;
}

/**
 *
 * @brief pomocna funkce pro nacteni domeny nebo IP adresy s portem ze zadaneho parametru
 * 
 * @param param parametr
 * @param args struktura obsahujici zaznamy argumentu
 * 
 * @returns true pokud se povedlo jinak false
 * 
 */
bool get_host_and_port(char *param, arguments *args){
    /* Rozdeli vstupni retezec na zaklade rozdelovace ":" */
    args->host = strtok(param, ":");
    args->port = atoi(strtok(NULL, ":"));

    /* Pokud se povedlo ziskat pozadovane zaznamy, vraci se true */
    if(args->host && args->port) return true;

    return false;
}

/**
 *
 * @brief pomocna funkce pro vypis chyb pri zpracovavani parametru
 * 
 * @param code udava o jaky typ chyby se jedna
 */
void print_error(int code){
    switch (code)
    {
    case 0:
        fprintf(stderr, "Collectors address is invalid!\n");
        break;
    case 1:
        fprintf(stderr, "Switch -a | --active is used incorrectly!\n");
        break;
    case 2:
        fprintf(stderr, "Switch -i | --inactive is used incorrectly!\n");
        break;
    case 3:
        fprintf(stderr, "Incorrect usage of [hostname | IP address]:PORT!\n");
        break;
    default:
        break;
    }
}

