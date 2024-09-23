/**
 *
 * @brief hlavni telo exporteru NetFlowv5 toku. Spojuje vsechny jednotlive moduly do jednoho.
 * @author Roman Machala
 * @date 21.09.2024
 *
 *   
 */ 

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>

#include "arg_parser.h"
#include "hash_table.h"
#include "exporter.h"

/**
 * 
 * @brief funkce zachycujici signal Ctrl-C
 * 
 */
void handle_signal(int sig){
    exit(0);
}


int main(int argc, char *argv[]){

    signal(SIGINT, handle_signal);  /* V pripade stisknuti Ctrl-C dojde k zavolani funkce handle_signal a dojde k adekvatnimu ukonceni programu */

    arguments args;     /* Struktura obsahujici parametry prikazove radky */
    if(!parse_arguments(&args, argv, argc)) return 1;     /* Zpracuje argumenty, vraci false v pripade chybejici pozadovane hodnoty (-i, -a) */

    if(!check_arguments(&args)) return 1;   /* Pokud nejsou zadany pozadovane parametry (host, port, PCAP soubor) */


    netflowv5 *flows[MAX_FLOW_LENGTH];  /* Inicializace hashovaci tabulky */
    init(flows);

    start_extraction(flows, &args);

    /* print_flows(flows); */

    clean_flows(flows);


    return 0;
}