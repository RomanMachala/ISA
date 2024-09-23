#ifndef HASH_TABLE_H
#define HASH_TABLE_H

/**
 * 
 * @brief Hlavickovy soubor pro hashovaci tabulku
 * @author Roman Machala
 * @date 23.09.2024
 * 
 */

#include<stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>



#define MAX_FLOW_LENGTH 1009        /* Definuje maximalni mozny pocet toku v jednu chvili (prvocislo) */

/**
 * 
 * @brief struktura reprezentujici NetFlowv5 zaznam
 * 
 * Obsah struktury odpovida jednotlivym polozkam, kjtere NetFlow v5 protokol pozaduje
 * Nalezeno zde: 
 *      https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html
 * 
 */
typedef struct NetFlowv5{
    uint32_t srcaddr;       /* Source IP address */
    uint32_t dstaddr;       /* Destiantion IP address */
    uint32_t nexthop;       /* IP address of next hop router */
    uint16_t input;         /* SNMP index of input interface */
    uint16_t output;        /* SNMP index of output interface */ 
    uint32_t dPkts;         /* Packets in the flow */
    uint32_t dOctets;       /* Total number of Layer 3 bytes in the packets of the flow */
    uint32_t first;         /* SysUptime at start of flow */
    uint32_t last;          /* SysUptime at the time the last packet of the flow was received */
    uint16_t srcport;       /* TCP/UDP source port number or equivalent */
    uint16_t dstport;       /* TCP/UDP destination port number or equivalent */
    uint8_t pad1;           /* Unused (zero) bytes */
    uint8_t tcp_flags;      /* Cumulative OR of TCP flags */
    uint8_t prot;           /* IP protocol type (for example, TCP = 6; UDP = 17) */
    uint8_t tos;            /* IP type of service (ToS) */
    uint16_t src_as;        /* Autonomous system number of the source, either origin or peer */
    uint16_t dst_as;        /* Autonomous system number of the destination, either origin or peer */
    uint8_t src_mask;       /* Source address prefix mask bits */
    uint8_t dst_mask;       /* Destination address prefix mask bits */
    uint16_t pad2;          /* Unused (zero) bytes */
} netflowv5;

/**
 * 
 * @brief hashovaci funkce pro hashovaci tabulku, dle specifikace CISCO : 
 *          https://www.cisco.com/c/dam/en/us/td/docs/security/stealthwatch/netflow/Cisco_NetFlow_Configuration.pdf
 * 
 *          NetFlow is based on 7 key fields
 *               • Source IP address
 *               • Destination IP address
 *               • Source port number
 *               • Destination port number
 *               • Layer 3 protocol type (ex. TCP, UDP)     -   neni uvazovan protokol, protoze zpracovavaji se pouze TCP protokoly
 *               • ToS (type of service) byte
 *               • Input logical interface
 * 
 *          je kazdy tok identifikovan unikatni kombinaci vyse uvedenych parametru, proto hashovaci funkce
 *          bere v potaz pouze vyse uvedene z aktualne zpracovavaneho toku, viz implementace v exporter.c
 * @param flow aktualne zpracovavany flow
 * 
 * @returns hash index
 * 
 */
int hash_function(netflowv5 *flow);

/**
 *
 * @brief pomocna funkce porovnavajici jednotlive toky
 * 
 * @param first prvni tok pro porovnani
 * @param second druhy tok pro porovnani
 * 
 * @returns true v pripade shodnych toku, jinak false
 *  
 */
bool compare_flows(netflowv5 *first, netflowv5 *second);

/**
 * 
 * @brief pomocna funkce, ktera spoji 2 toku do jednoho
 * 
 * @param first prvni tok
 * @param druhy tok
 * 
 */
void update_flow(netflowv5 *first, netflowv5 *second);

/**
 * 
 * @brief funkce pro vkladani noveho toku do hashovaci tabulky, zajistuje kolize a spojeni 2 toku v pripade identickych klicu
 * 
 * @param flows hashovaci tabulka obsahujici informace o vsech tocich
 * @param current_flow novy tok pro vlozeni do tabulky (nebo pro slouceni s jinym)
 * 
 */
void insert_into_table(netflowv5 **flows, netflowv5 *current_flow);

/**
 *
 * @brief funkce starajici se o uvolneni hashovaci tabulky
 * 
 * @param flows hashovaci tabulka obsahujici zaznamy o vsech tocich 
 * 
 */
void clean_flows(netflowv5 **flows);

void print_flows(netflowv5 **flows);

void init(netflowv5 **flows);

#endif