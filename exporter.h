#ifndef EXPORTER_H
#define EXPORTER_H

/**
 * 
 * @brief
 * @author Roman Machala
 * @date 23.09.2024
 * 
 */
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "hash_table.h"
#include "arg_parser.h"

/**
 * 
 * @brief hlavni funkce pro exporter, otevre soubor a nasledne zacne zpracovavat zachycene pakety
 * 
 * @param flows hashovaci tabulka obsahujici informace o vsech tocich
 * @param args vstupni argumenty programu
 * 
 */
bool start_extraction(netflowv5 **flows, arguments *args);

void packet_handler(uint8_t *user, const struct pcap_pkthdr *pkthdr, const uint8_t *packet);


#endif