/**
 *
 * @brief   
 * @author Roman Machala 
 * @date 23.09.2024
 * 
 */


#include "exporter.h"

char err_buff[PCAP_ERRBUF_SIZE];    /* error buffer pro pcap_open_offline() */

void packet_handler(uint8_t *user, const struct pcap_pkthdr *pkthdr, const uint8_t *packet){

    packet_handling *handler = (packet_handling *)user; /* Prevedeni uzivatelskeho parametru zpet na strukturu packet_handling */

    /* Pred kazdym zpracovanim paket projde vsechny stavajici toky a zjisti, jestli nejsou neaktivni */
    if(!check_for_inactive_flows(handler->flows, handler->args  )){
        handler->result = false;
        return;
    }

    struct ethhdr *ether_header = (struct ethhdr*)packet;
    if(ether_header->h_proto != ETHERTYPE_IP) return;   /* Pokud se nejedna o IP paket nezpracovavame */

    /* pro zisk ip hlavicky musime preskocit ethernet hlavicku */
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    if(!(ip_header->protocol == IPPROTO_TCP)) return;   /* Pokud se nejedna o TCP protokol, nezpracovavame */

    /* ziskame TCP hlavicku */
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + (ip_header->ihl * 4));

    netflowv5 *new_flow = (netflowv5 *)malloc(sizeof(struct NetFlowv5));
    if(!new_flow){
        fprintf(stderr, "Couldn't create another flow due to malloc error!\n");
        return;
    }

    uint32_t packet_time_s = (pkthdr->ts.tv_sec * 1000); 
    /* Zisk casu zachyceni paketu */
    
    /* Vyplnime vsechny informace z prijate pakety, pokud nelze specifikovat nechavame prazdne*/
    new_flow->srcaddr = ip_header->saddr;
    new_flow->dstaddr = ip_header->daddr;

    new_flow->dPkts = 1;    /* Pocet paket v toku */
    new_flow->dOctets = ntohs(ip_header->tot_len);  /* Velikost IP hlavicky a dat */

    /* Aktualizace zachyceni casu */
    new_flow->first = packet_time_s;
    new_flow->last = packet_time_s;

    /* Source a destination port */
    new_flow->srcport = tcp_header->th_sport;
    new_flow->dstport = tcp_header->th_dport;

    new_flow->tcp_flags = tcp_header->th_flags;
    new_flow->prot = ip_header->protocol;
    new_flow->tos = ip_header->tos;

    struct timeval tv;
    gettimeofday(&tv, NULL); /* Ziska aktualni cas */

    new_flow->current_time = tv.tv_sec; /* Zajimaji nas pouze sekundy */

    netflowv5 *inserted = NULL;
    bool export = false;
    bool result = true;

    netflowv5 *flow = get_flow(handler->flows, new_flow);    
    if(flow && check_for_active(flow, new_flow, handler->args->active_timeout)){   /* Pokud zaznam jiz existuje a vyprsel aktivni timeout */
        result = export_flow(flow, handler->args);  /* Exportneme stary tok */
    }

    inserted = insert_into_table(handler->flows, new_flow); /* Vytvorime novy tok */
    export = check_for_flags(inserted);

    if(export){
        result = export_flow(inserted, handler->args);
        
    }

    if(!result){
        (*handler->result) = false; /* Nastavime flag pro udani nepodareneho odeslani toku */
        return;
    }

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

bool export_flow(netflowv5 *flow, arguments *args){
    printf("Exporting a flow!\n");
    return true;
}

bool check_for_active(netflowv5 *flow1, netflowv5 *flow2, int timeout){
    /* Aktivni timeout stanovuje dobu, po ktere je tok odeslan na kolektor i kdyz je tok stale aktivni */

    return !((flow1->current_time - flow2->current_time) < timeout);
}

bool check_for_inactive(netflowv5 *flow ,int timeout){
    /* Neaktivni timeout stanovuje dobu, po kterou je tok neaktivni, pokud presahne danou hranici, je uzavren a odeslan na kolektor */

    struct timeval tv;
    gettimeofday(&tv, NULL);

    return !((tv.tv_sec - flow->current_time) < timeout);
}

bool check_for_inactive_flows(netflowv5 **flows, arguments *args){
    for(int i = 0; i < MAX_FLOW_LENGTH; i++){
        if(flows[i] && check_for_inactive(flows[i], args->active_timeout)){
            bool result = export_flow(flows[i], args);
            if(!result) return false;
        }
    }

    return true;
}

bool clean_exporting(netflowv5 **flows, arguments *args){
    for(int i = 0; i < MAX_FLOW_LENGTH; i++){
        if(flows[i]){
            bool result = export_flow(flows[i], args);
            if(!result) return false;
        }
    }

    return true;
}
