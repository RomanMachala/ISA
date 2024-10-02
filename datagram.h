#ifndef DATAGRAH_H
#define DATAGRAM_H

#define MAX_NUMBER_FLOWS 30

#include "hash_table.h"

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

extern ProcessedFlows set;

void add_flow(netflowv5 *flow);

bool export_set();

void print_ip_addr(char *temp ,uint32_t ip_address);


#endif