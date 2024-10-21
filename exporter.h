#ifndef EXPORTER_H
#define EXPORTER_H

/**
 * 
 * @author Roman Machala (xmacha86)
 * @date 23.09.2024
 * 
 * @brief hlavickovy soubor pro zakladni logiku exporteru a zpracovani paket
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
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "hash_table.h"
#include "arg_parser.h"

#define NETFLOW_V5_VERSION 5 /* Pevne dana verze NetFLow protokolu */

/* Externi promenna, udavajici SySUptime, tedy cas od zapnuti exporteru, dostupna odkudkoli */
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
 * @returns true v pripade prubehu bez chyby, jinak false (propagace selhani exportu v pripade naplneni setu)
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
 * @brief pomocna funkce pro kontrolu aktivniho timeoutu
 * 
 * @param flow1 puvodni tok
 * @param flow2 novy zachyceny paket patrici do stejneho toku jako flow1
 * @param timeout aktivni timeout v s
 * 
 * @returns true v priapade, ze tok jiz expiroval v ramci aktivnihi timeoutu, jinak false
 * 
 */
bool check_for_active(netflowv5 *flow1, netflowv5 *flow2,  int timeout);

/**
 * 
 * @brief pomocna funkce pro kontrolu neaktivniho timeoutu
 * 
 * @param flow1 puvodni tok
 * @param flow2 novy paket, patrici do stejneho toku jako flow1
 * @param timeout neaktivni timeout v s
 * 
 * @returns true v pripade expirace toku v ramci neaktivniho timeoutu, jinak false
 * 
 */
bool check_for_inactive(netflowv5 *flow1, netflowv5 *flow2, int timeout);


/**
 * 
 * @brief funkce kontrolujici zdali existuje nejaky tok, jez expiroval v ramci timeoutu nebo flagu
 * 
 * @param flows hashovaci tabulka obsahujici zaznamy o tocich
 * 
 * @returns true v pripade uspesneho exportovani vsech expirovanych toku, jinak false
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

/**
 * 
 * @brief funkce zajistujici export datagramu obsahujici X pocet toku na kolektor
 * 
 * @param args vstupni argumnety
 * 
 * @returns true v pripade povedeneho exportu, jinak false
 * 
 */
bool export_datagram(arguments *args);

#endif