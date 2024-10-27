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
#include "datagram.h"

/**
 * 
 * @brief funkce zachycujici signal Ctrl-C
 * 
 * @param sig signal
 * 
 */
void handle_signal(int sig){
    exit(0);
}

struct timeval tv;  /* Reprezentuje cas spusteni exporteru */

int main(int argc, char *argv[]){

    gettimeofday(&tv, NULL);    /* Simulace SysUptime */

    signal(SIGINT, handle_signal);  /* V pripade stisknuti Ctrl-C dojde k zavolani funkce handle_signal a dojde k adekvatnimu ukonceni programu */

    arguments args;     /* Struktura obsahujici parametry prikazove radky */
    if(!parse_arguments(&args, argv, argc)) exit(1);     /* Zpracuje argumenty, vraci false v pripade chybejici pozadovane hodnoty (-i, -a) */

    if(!check_arguments(&args)) exit(1);   /* Pokud nejsou zadany pozadovane parametry (host, port, PCAP soubor) */

    if(args.debug) print_params(&args);

    netflowv5 *flows[MAX_FLOW_LENGTH];  /* Inicializace hashovaci tabulky */
    bool result = true;
    packet_handling handler = {flows, &args, &result};

    init(flows);
    start_extraction(&handler); /* Spusti hlavni telo, zpracovavajici pakety ze souboru a nasledne jejich export */

    export_datagram(&args); /* Exporte zbyajici, pokud jdou, toky z tabulky */

    clean_flows(flows); /* Uvolni pamet */

    free(args.address_hostname);


    return 0;
}