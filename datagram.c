/**
 *
 * @author Roman Machala
 * @date 03.10.2024
 *
 * @brief soubor obsahujici implementaci logiky pro praci s datagramy obsahujici jednotlive toky pro exportovani
 *   
 */ 

#include "datagram.h"

/**
 * 
 * @brief funkce pridavajici toky pripravene pro export do setu
 * 
 * @param flow tok
 * 
 */
void add_flow(netflowv5 *flow){
    set.count += 1;     /* Inkrementace poctu toku v setu */
    set.total_count += 1;
    set.flows[set.count - 1] = (netflowv5 *)malloc(sizeof(struct NetFlowv5));
    if(!set.flows[set.count -1]){
        return;
    }

    copy_flow(set.flows[set.count - 1], flow);
}

/**
 *
 * @brief pomocna funkce pro kontrolu, zda je set pripraven pro export
 * 
 * @returns true v pripade, ze tok je pripraven pro export, jinak false 
 * 
 */
bool export_set(){
    return set.count == MAX_NUMBER_FLOWS;    /* V pripade dosazeni 30 toku v setu */
}

/**
 * 
 * @brief pomocna funkce pro vypis IP adresy ve formatu X.X.X.X, pro debugovaci ucel
 * 
 * @param temp retezec, jez ma byt vypsan pred samotnou adresou (napr. "src" | "dst" )
 * @param ip_address samotna ip adresa, jez ma byt vypsana
 * 
 */
void print_ip_addr(char *temp ,uint32_t ip_address){
    struct in_addr ip;
    ip.s_addr = ip_address;

    char *ip_addr = inet_ntoa(ip);

    printf("%s:%s", temp, ip_addr);
}

void convert_flow_to_network_order(netflowv5 *flow){
    flow->dPkts = htonl(flow->dPkts);
    flow->dOctets = htonl(flow->dOctets);
    flow->first = htonl(flow->first);
    flow->last = htonl(flow->last);
}
