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
#include <sys/time.h>

#include "hash_table.h"
#include "arg_parser.h"

extern struct timeval tv;


/**
 * 
 * @brief pomocna struktura pro predani packet_handler() funcki 
 * 
 */
typedef struct packet_handling{
    netflowv5 **flows;  /* Hashovaci tabulka */
    arguments *args;    /* Argumenty prikazove radky */
    bool *result;       /* Flag udavajici povedeni/selhani odeslani vsech toku */
}packet_handling;

/**
 * 
 * @brief hlavni funkce pro exporter, otevre soubor a nasledne zacne zpracovavat zachycene pakety
 * 
 * @param flows hashovaci tabulka obsahujici informace o vsech tocich
 * @param args vstupni argumenty programu
 * 
 * @returns true v pripade povedene extrakce vsech toku, jinak false
 * 
 */
bool start_extraction(packet_handling *handler);

/**
 *
 * @brief funkce zpracovavajici zachycene pakety z PCAP souboru
 * 
 * @param user uzivatelske parametry (pouzito pro predani hashovaci tabulky)
 * @param pkthdr hlavicka zachycene PCAP pakety
 * @param packet payload pakety (obsahuje hlavicky a data)
 *  
 */
void packet_handler(uint8_t *user, const struct pcap_pkthdr *pkthdr, const uint8_t *packet);

/**
 * 
 * @brief funkce pridavajici tok do setu pro export
 * 
 * @param flow tok pro pridani
 * 
 * @returns true v pripade povedeneho odeslani, jinak false
 * 
 */
bool handle_flow(netflowv5 *flow, arguments *args);

/**
 *
 * @brief pomocna funkce, kontroluje, zdali se dany tok jiz nema odeslat
 * 
 * @param flow tok pro kontrolu
 * 
 * @returns true v pripade potvrzeni toku pro odeslani, jinak false
 *  
 */
bool check_for_flags(netflowv5 *flow);

/**
 * 
 * @brief pomocna funkce, ktera pred aktualizaci toku zjisti, zdali dany tok jiz nepresahl aktivni dobu
 * 
 * @param flow puvodni tok
 * @param timeout aktivni timeout v sekundach
 * 
 * @returns truen v pripade ze puvodni tok ma byt exportovan, jinak false - slozueni toku
 * 
 */
bool check_for_active(netflowv5 *flow1, netflowv5 *flow2,  int timeout);

/**
 * 
 * @brief pomocna funkce kontrolujici, zdali dany tok je neaktivni
 * 
 * @param flow tok pro kontrolu
 * @param timeout neaktivni timeout v sekundach
 * 
 * @returns true v pripade ze tok je neaktivni, jinak false - nebude exportovan  
 * 
 */
bool check_for_inactive(netflowv5 *flow1, netflowv5 *flow2, int timeout);


/**
 * 
 * @brief funkce kontrolujici zdali existuje nejaky tok, co je neaktivni
 * 
 * @param flows hashovaci tabulka obsahujici zaznamy o tocich
 * 
 * @returns true v pripade uspesneho exportovani vsech neaktivnich toku, false v priapde chyby exportu
 * 
 */
bool check_for_expired_flows(netflowv5 **flows, netflowv5 *flow, arguments *args);

/**
 * 
 * @brief funkce urcena pro uklid po exportu, zajistuje export vsech toku, ktere zustaly v tabulce po dokonceni analyzy PCAP souboru
 * 
 * @param flows hashovaci tabulka obsahujici zaznamy o tocich
 * 
 * @returns true v pripade povedeneho exprortu, false v pripade vyskytu chyby
 * 
 */
bool clean_exporting(netflowv5 **flows, arguments *args);

bool export_datagram(arguments *args);

#endif