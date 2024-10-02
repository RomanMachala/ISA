/**
 *
 * @brief   
 * @author Roman Machala 
 * @date 23.09.2024
 * 
 */


#include "exporter.h"
#include "datagram.h"

char err_buff[PCAP_ERRBUF_SIZE];    /* error buffer pro pcap_open_offline() */  

ProcessedFlows set;


void packet_handler(uint8_t *user, const struct pcap_pkthdr *pkthdr, const uint8_t *packet){

    packet_handling *handler = (packet_handling *)user; /* Prevedeni uzivatelskeho parametru zpet na strukturu packet_handling */

    struct ethhdr *ether_header = (struct ethhdr*)packet;
    if(ntohs(ether_header->h_proto) != ETHERTYPE_IP){
        return;
    }   /* Pokud se nejedna o IP paket nezpracovavame */

    /* pro zisk ip hlavicky musime preskocit ethernet hlavicku */
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    if(!(ip_header->protocol == IPPROTO_TCP)){
        return;
    }   /* Pokud se nejedna o TCP protokol, nezpracovavame */


    /* ziskame TCP hlavicku */
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + (ip_header->ihl * 4));

    netflowv5 *new_flow = (netflowv5 *)malloc(sizeof(struct NetFlowv5));
    if(!new_flow){
        fprintf(stderr, "Couldn't create another flow due to malloc error!\n");
        return;
    }
    
    /* Vyplnime vsechny informace z prijate pakety, pokud nelze specifikovat nechavame prazdne*/
    new_flow->srcaddr = ip_header->saddr;
    new_flow->dstaddr = ip_header->daddr;

    new_flow->dPkts = 1;    /* Pocet paket v toku */
    new_flow->dOctets = ntohs(ip_header->tot_len);  /* Velikost IP hlavicky a dat */

    /* Aktualizace zachyceni casu */
    new_flow->first = pkthdr->ts.tv_sec - tv.tv_sec;
    new_flow->last = pkthdr->ts.tv_sec - tv.tv_sec;

    /* Source a destination port */
    new_flow->srcport = tcp_header->th_sport;
    new_flow->dstport = tcp_header->th_dport;

    new_flow->tcp_flags = tcp_header->th_flags;
    new_flow->prot = ip_header->protocol;
    new_flow->tos = ip_header->tos;

    bool result = check_for_expired_flows(handler->flows, new_flow, handler->args);
    if(!result){
        handler->result = false;
        return;
    }
    insert_into_table(handler->flows, new_flow);


}

bool start_extraction(packet_handling *handler){
    pcap_t *handle = pcap_open_offline(handler->args->file_path, err_buff);  /* Otevre soubor se zachycenymi packetami */
    /* Pokud se nepodari otevrit soubor, vypise se chyba zachycena v error bufferu a vraci se false */
    if(!handle){
        fprintf(stderr, "%s\n", err_buff);
        return false;
    } 

    /* Zpracovani paketu, 0 znamena 'nekonecne' paket nebo do konce souboru */
    pcap_loop(handle, 0, packet_handler, (uint8_t *)handler);


    pcap_close(handle); /* Uzavre soubor  */


    return ((*handler->result) && clean_exporting(handler->flows, handler->args));    /* Vraceni flagu udavajiciho stav exprortu toku a exportu vsech zbyvajicich toku*/ 
}

bool check_for_flags(netflowv5 *flow){
    /**
     * 
     * Odeslani toku muze nastat v techto pripadech: 
     *      aktivni timeout
     *      neaktivni timeout
     *      ukonceni spojeni (FIN x RST flag)
     * 
     */

    /* RST a FIN timeout */

    return (flow->tcp_flags & TH_RST || flow->tcp_flags & TH_FIN);

    /* aktivni a neaktivni timeout jsou kontrolovany pri zachyceni jednotlivych paket */
}

bool handle_flow(netflowv5 *flow, arguments *args){
    add_flow(flow); /* prida tok do setu */
    if(export_set()){
        return export_datagram(args);    /* Pokud jiz je pozadovany pocet toku v setu */
    }      

    return true;
}

bool check_for_active(netflowv5 *flow1, netflowv5 *flow2, int timeout){

    return abs(abs(flow1->first) - abs(flow2->first)) > timeout; 
    
}

bool check_for_inactive(netflowv5 *flow1, netflowv5 *flow2 ,int timeout){
    return abs(abs(flow1->last) - abs(flow2->first)) > timeout;
}

bool check_for_expired_flows(netflowv5 **flows, netflowv5 *flow, arguments *args){
    netflowv5 *old_flow = get_flow(flows, flow);    /* Ziska jiz existujici flow */

    if(!old_flow) return true;  /* Pokud takova flow neexistuje, neni co resit */

    if(check_for_active(old_flow, flow, args->active_timeout)){
        printf("Vyprsel aktivni timeout, rozdil je:%d\n\n", abs(abs(old_flow->first) - abs(flow->last)));
        bool result = handle_flow(old_flow, args);
        if(!result) return false;
    }else if(check_for_inactive(old_flow, flow, args->inactive_timeout)){
        printf("Vyprsel inaktivni timeout, rozdil je: %d\n\n", abs(abs(old_flow->last)- abs(flow->first)));
        bool result = handle_flow(old_flow, args);
        if(!result) return false;
    }

    return true;
}

bool clean_exporting(netflowv5 **flows, arguments *args){
    for(int i = 0; i < MAX_FLOW_LENGTH; i++){
        if(flows[i]){
            bool result = handle_flow(flows[i], args);
            if(!result) return false;
        }
    }

    return true;
}

bool export_datagram(arguments *args){

    /* Prvni ziskame IP adresu kolektoru */

    

    /* TODO logika pro odeslani UDP paket */


    /* Resetujeme counter toku v setu */
    set.count = 0;



    /* Je treba uvolnit vsechny alokovane mista */

    for(int i = 0; i < MAX_NUMBER_FLOWS; i++){
        if(!set.flows[i]){
            continue;
        }
        //free(set.flows[i]); 
        print_ip_addr("src", set.flows[i]->srcaddr);
        printf(":%u", ntohs(set.flows[i]->srcport));
        printf("\t\t");
        print_ip_addr("dst", set.flows[i]->dstaddr);
        printf(":%u", ntohs(set.flows[i]->dstport));
        printf("\n");
        printf("Number of pacekts: %d\n", set.flows[i]->dPkts);
        printf("Bytes: %dB\n", set.flows[i]->dOctets);
        printf("\n\n");
        free(set.flows[i]);
        set.flows[i] = NULL;
    }

    return true;
}
