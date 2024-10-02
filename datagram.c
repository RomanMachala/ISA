#include "datagram.h"

void add_flow(netflowv5 *flow){
    set.count += 1;     /* Inkrementace poctu toku v setu */
    set.total_count += 1;
    set.flows[set.count - 1] = (netflowv5 *)malloc(sizeof(struct NetFlowv5));
    if(!set.flows[set.count -1]){
        return;
    }

    copy_flow(set.flows[set.count - 1], flow);
    
}

bool export_set(){
    return set.count == MAX_NUMBER_FLOWS;    /* V pripade dosazeni 30 toku v setu */
}

void print_ip_addr(char *temp ,uint32_t ip_address){
    struct in_addr ip;
    ip.s_addr = ip_address;

    char *ip_addr = inet_ntoa(ip);

    printf("%s:%s", temp, ip_addr);
}
