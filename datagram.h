/**
 *
 * @author Roman Machala (xmacha86)
 * @date 03.10.2024
 *
 * @brief hlavickovy soubor pro logiku prace s datagramy obsahujici toky pro export
 *   
 */ 


#ifndef DATAGRAH_H
#define DATAGRAM_H

#define MAX_NUMBER_FLOWS 30     /* Maximalni pocet toku v ramci jendoho datagramu */

#include "hash_table.h"

/**
 * 
 * @brief struktrua reprezentujici hlavicku datagramu
 * 
 */
typedef struct NetFlowHeader {
    uint16_t version;           /* NetFlow export format version num */
    uint16_t count;             /* Number of exported flows */
    uint32_t sysUptime;         /* Current time in ms since start */
    uint32_t unix_secs;         /* Current count of seconds since CUT */
    uint32_t unix_nsecs;        /* Residual nanoseconds since CUT */
    uint32_t flow_sequence;     /* Sequence cnt of total flows seen */
    uint8_t engine_type;        /* Type of flow-switching engine */
    uint8_t engine_id;          /* Slot num of flow-switching engine */
    uint16_t sampling_interval; /* Sampling mode + interval (2b - 14b) */
} NetFlowHeader;

/**
 * 
 * @brief struktura pro uchovani jiz zpracovanych toku, uchovava 
 *      jednotlive toky, doku jich nebude pozadovany pocet pro export 
 */
typedef struct ProcessedFlows{
    int count;                              /* Pocet toku v datagramu */
    int total_count;                        /* Celkovy pocet toku */
    netflowv5 *flows[MAX_NUMBER_FLOWS];     /* Jednotlive toky v datagramu */
}ProcessedFlows;

/**
 * 
 * @brief externi promenna reprezentujici jiz zpracovane toky, cekajici na export
 * 
 */
extern ProcessedFlows set;

/**
 * 
 * @brief pomocna funkce vkladajici tok do setu 
 * 
 * @param flow vkladany tok
 * 
 */
void add_flow(netflowv5 *flow);

/**
 * 
 * @brief pomocna funkce pro kontrolu, zda je tok pripraven pro export
 * 
 * @returns true v pripade ze je tok pripraven pro export, jinak false
 * 
 */
bool export_set();

/**
 * 
 * @brief pomocna funkce pro vypis IP adresy ve formatu X.X.X.X, pro deubugovaci ucely
 * 
 * @param temp retezec, co ma byt vypsan pred IP adresou (napr. "src" | "dst")
 * @param ip_address ip adresa pro vypsani
 * 
 */
void print_ip_addr(char *temp ,uint32_t ip_address);


/**
 * 
 * @brief pomocna funkce pro konverzi host to network informaci pred exportem
 * 
 * @param flow tok, jez ma byt exportovan
 * 
 */
void convert_flow_to_network_order(netflowv5 *flow);

#endif