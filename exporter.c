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

ProcessedFlows set; /* Externi promenna, reprezentuje toky pripravene pro export */

/**
 * 
 * @brief hlavni funkce zpracovavajici pakety
 * 
 * @param user uzivatelske parametry
 * @param pkthdr PCAP hlavicka zachycene pakety
 * @param packet zachycena paketa
 * 
 */
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
    new_flow->dOctets = pkthdr->len - 14;  /* Velikost IP hlavicky a dat */

    /* Aktualizace zachyceni casu v ms*/
    new_flow->first = (pkthdr->ts.tv_sec - tv.tv_sec) * 1000 + (pkthdr->ts.tv_usec - tv.tv_usec) / 1000;
    new_flow->last = (pkthdr->ts.tv_sec - tv.tv_sec) * 1000 + (pkthdr->ts.tv_usec - tv.tv_usec) / 1000;

    /* Source a destination port */
    new_flow->srcport = tcp_header->th_sport;
    new_flow->dstport = tcp_header->th_dport;

    new_flow->tcp_flags = tcp_header->th_flags;
    new_flow->prot = ip_header->protocol;
    new_flow->tos = ip_header->tos;

    /* Zbytek vyplnime nulami */

    new_flow->nexthop = 0;
    new_flow->input = 0;
    new_flow->output = 0;
    new_flow->pad1 = 0;
    new_flow->src_as = 0;
    new_flow->dst_as = 0;
    new_flow->src_mask = 0;
    new_flow->dst_mask = 0;
    new_flow->pad2 = 0;

    /**
     * 
     * Zkontrolujeme expirovane toky
     * Pokud nejaky tok napriklad expiruje v ramci aktivniho timeoutu, je ulozen do setu (toky pripravene pro export)
     * nova zachycena paketa pak tvori zcela novy tok 
     * 
     */
    bool result = check_for_expired_flows(handler->flows, new_flow, handler->args);
    if(!result){
        handler->result = false;
    }
    /* Vlozime do tabulky, budto jako novy tok nebo aktualizaci jiz existujiciho toku */
    insert_into_table(handler->flows, new_flow);

}

/**
 *
 * @brief funkce zacinajici "etapu" zacatku extrakce paket ze souboru
 * 
 * @param handler struktura obsahujici vsechny potrebne polozky pro zpracovani paket (hashovaci tabulku, argymenty, ..)
 * 
 * @returns true v pripade povedene extrakce jinak false 
 * 
 */
bool start_extraction(packet_handling *handler){
    pcap_t *handle = pcap_open_offline(handler->args->file_path, err_buff);  /* Otevre soubor se zachycenymi packetami */
    /* Pokud se nepodari otevrit soubor, vypise se chyba zachycena v error bufferu a vraci se false */
    if(!handle){
        fprintf(stderr, "%s\n", err_buff);
        return false;
    } 

    /* Zpracovani paketu, 0 znamena 'nekonecne' paket nebo do konce souboru, vlozime handler jako uzivatelsky parametr */
    pcap_loop(handle, 0, packet_handler, (uint8_t *)handler);


    pcap_close(handle); /* Uzavre soubor  */


    return ((*handler->result) && clean_exporting(handler->flows, handler->args));    /* Vraceni flagu udavajiciho stav exprortu toku a exportu vsech zbyvajicich toku*/ 
}

/**
 * 
 * @brief pomocna funkce pro kontrolu expiraci toku v ramci prijeti RST nebo FIN timeout
 * 
 * @param flow tok pro kontrolu
 * 
 * @returns true v pripade expirace, jinak false
 * 
 */
bool check_for_flags(netflowv5 *flow){

    /* RST a FIN timeout */

    return (flow->tcp_flags & TH_RST || flow->tcp_flags & TH_FIN);
}

/** 
 * 
 * @brief funkce pro zpracovani expirovaneho/uzavreneho toku 
 * 
 * @param flow expirvany nebo uzavreny tok
 * @param args vstupni argumenty
 * 
 * @returns true v priapde povedeneho zpracovani, jinak false
 * 
 */
bool handle_flow(netflowv5 *flow, arguments *args){
    add_flow(flow); /* prida tok do setu */
    if(export_set()){
        return export_datagram(args);    /* Pokud jiz je pozadovany pocet toku v setu */
    }      

    return true;
}

/**
 * 
 * @brief pomocna funkce pro kontrolu expirace toku v ramci aktivniho timeoutu
 * 
 * @param flow1 puvodni tok 
 * @param flow2 novy tok, shodny s tokem 1 pro kontrolu expirace
 * @param timeout aktivni timeout
 * 
 * @return true v pripade expirace, jinak false
 * 
 */
bool check_for_active(netflowv5 *flow1, netflowv5 *flow2, int timeout){

    /**
     * 
     * Kontroluje, zdali aktualizovanim toku flow1 o flow2
     * nedojde k prekroceni aktivniho timeoutu
     * Pokud tak nasytane, je tok povazovan za expirovany v ramci aktivniho toku
     * 
     * flow2->first by po aktualizaci toku predstavovala posledni prijatou paketu
     * 
     * pocitame tedy rozdil mezi prvni prijatou v toku a posledni paketou, ktera do toku "patri"
     * 
     */
    return abs(abs(flow1->first) - abs(flow2->first)) > (timeout * 1000); 
    
}

/**
 * 
 * @brief pomocna funkce pro kontrolu expirace v ramci neaktivniho timeoutu
 * 
 * @param flow1 puvodni tok
 * @param flow2 novy tok, shodny s tokem 1 pro kontrolu expirace 
 * @param timeout neaktivni timeout
 * 
 * @returns true v pripade expirace, jinak false
 * 
 */
bool check_for_inactive(netflowv5 *flow1, netflowv5 *flow2 ,int timeout){

    /**
     * 
     * Kontroluje, zdali aktualizaci toku flow1 o flow2
     * neodojde k poruseni neaktivniho timeoutu 
     * Pokud tak nastane, je tok povazovan za expirovany
     * 
     * flow1->last je posledni paketa v ramci jiz zkontrolovaneho toku
     * flow2->first je cas prijeti pakety, ktera by mela byt zarazena do toku flow1
     * 
     * kontrolujeme, zdali casovy rozdil mezi temito 2 paketami neni vetsi nez neaktivni timeou
     * V pripade, ze je vetsi, paketa byla minimalne timeout sekund neaktivni, tedy expirovala v ramci neaktivniho timeoutu
     * 
     */
    return abs(abs(flow1->last) - abs(flow2->first)) > (timeout * 1000);
}

/**
 * 
 * @brief kontrola, zdali neexistuje nejaky expirovany tok
 * 
 * @param flows hashovaci tabulka obsahujici vsechny zpracovavane toky
 * @param flow novy vytvoreny tok pro kontrolu
 * @param args vstupni argumenty
 * 
 * @returns true v pripade povedeneho zpracovani, jinak false
 * 
 */
bool check_for_expired_flows(netflowv5 **flows, netflowv5 *flow, arguments *args){
    netflowv5 *old_flow = get_flow(flows, flow);    /* Ziska jiz existujici tok */

    if(!old_flow) return true;  /* Pokud takovy tok neexistuje, neni co resit */

    /* Zkontroluje toky na jednotlive timeouty */
    if(check_for_active(old_flow, flow, args->active_timeout)){
        //printf("Vyprsel aktivni timeout, rozdil je:%d\n\n", abs(abs(old_flow->first) - abs(flow->last)));
        bool result = handle_flow(old_flow, args);
        if(!result) return false;
    }else if(check_for_inactive(old_flow, flow, args->inactive_timeout)){
        //printf("Vyprsel inaktivni timeout, rozdil je: %d\n\n", abs(abs(old_flow->last)- abs(flow->first)));
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
    /* Ziskame aktualni cas */
    struct timespec current_time;
    clock_gettime(CLOCK_REALTIME, &current_time);

    /* Vytvorime datagramovou hlavicku */
    NetFlowHeader header;
    memset(&header, 0, sizeof(struct NetFlowHeader));
    header.version              = htons(NETFLOW_V5_VERSION);
    header.count                = htons(set.count);
    header.sysUptime            = htonl((current_time.tv_sec - tv.tv_sec) * 1000);  /* Zjistime cas od spusteni exporteru */ 
    header.unix_secs            = htonl(current_time.tv_sec);
    header.unix_nsecs           = htonl(current_time.tv_nsec);
    header.flow_sequence        = htonl(set.total_count - set.count);
    /* TODO logika pro odeslani UDP paket */

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sock < 0){
        //todo clean
        exit(1);
    }

    struct sockaddr_in collector_addr;
    memset(&collector_addr, 0, sizeof(struct sockaddr_in));
    collector_addr.sin_family = AF_INET;
    collector_addr.sin_port = htons(args->port);
    inet_pton(AF_INET, args->address_hostname, &collector_addr.sin_addr);

    size_t packet_size = sizeof(header) + sizeof(struct NetFlowv5) * set.count;
    uint8_t *buffer = malloc(packet_size);
    if(buffer == NULL){
        //todo clean
        exit(1);
    }

    memcpy(buffer, &header, sizeof(header));

    for(int i = 0; i < set.count; i++){
        convert_flow_to_network_order(set.flows[i]);
        memcpy(buffer + sizeof(header) + (i * sizeof(struct NetFlowv5)), set.flows[i], sizeof(struct NetFlowv5));
    }

    ssize_t sent_bytes = sendto(sock, buffer, packet_size, 0, (struct sockaddr*)&collector_addr, sizeof(struct sockaddr_in));
    if(sent_bytes < 0){
        exit(1);
        //todo clean
    }

    free(buffer);
    close(sock);

    /* Resetujeme counter toku v setu */
    set.count = 0;



    /* Je treba uvolnit vsechny alokovane mista */

    for(int i = 0; i < MAX_NUMBER_FLOWS; i++){
        if(!set.flows[i]){
            continue;
        }
        //free(set.flows[i]); 
        //print_ip_addr("src", set.flows[i]->srcaddr);
       // printf(":%u", ntohs(set.flows[i]->srcport));
        //printf("\t\t");
        //print_ip_addr("dst", set.flows[i]->dstaddr);
        //printf(":%u", ntohs(set.flows[i]->dstport));
        //printf("\n");
        //printf("Number of pacekts: %d\n", ntohl(set.flows[i]->dPkts));
        //printf("Bytes: %dB\n", ntohl(set.flows[i]->dOctets));
        //printf("\n\n");
        free(set.flows[i]);
        set.flows[i] = NULL;
    }
    return true;
}
