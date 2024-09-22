/**
 *
 * @author Roman Machala
 * @date 21.09.2024
 *
 *   
 */ 

#include "arg_parser.h"

int main(int argc, char *argv[]){

    arguments args;     /* Struktura obsahujici parametry prikazove radky */
    if(!parse_arguments(&args, argv, argc)) return 1;     /* Zpracuje argumenty, vraci false v pripade chybejici pozadovane hodnoty (-i, -a) */

    if(!check_arguments(&args)) return 1;   /* Pokud nejsou zadany pozadovane parametry (host, port, PCAP soubor) */

    return 0;
}