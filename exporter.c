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
    netflowv5 **flows = (netflowv5 **)user; /* Prevedeni uzivatelskeho parametru zpet na hashovaci tabulku */
    /* pro zisk ip hlavicky musime preskocit ethernet hlavicku */
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    if(!(ip_header->protocol == IPPROTO_TCP)) return;   /* Pokud se nejedna o TCP protokol, nezpracovavame */

    netflowv5 *new_flow = (netflowv5 *)malloc(sizeof(struct NetFlowv5));
    if(!new_flow){
        fprintf(stderr, "Couldn't create another flow due to malloc error!\n");
        return;
    }
    /* Ziskame informace z ip hlavicky */
    new_flow->srcaddr = ip_header->saddr;
    new_flow->dstaddr = ip_header->daddr;
    new_flow->tos = ip_header->tos;
    new_flow->prot = ip_header->protocol;
    new_flow->dPkts = 1;



    

    insert_into_table(flows, new_flow);

}

bool start_extraction(netflowv5 **flows, arguments *args){
    pcap_t *handle = pcap_open_offline(args->file_path, err_buff);  /* Otevre soubor se zachycenymi packetami */
    /* Pokud se nepodari otevrit soubor, vypise se chyba zachycena v error bufferu a vraci se false */
    if(!handle){
        fprintf(stderr, "%s\n", err_buff);
        return false;
    } 

    /* Zpracovani paketu, 0 znamena 'nekonecne' paket nebo do konce souboru */
    pcap_loop(handle, 0, packet_handler, (uint8_t *)flows);


    pcap_close(handle); /* Uzavre soubor  */

    return true;    /* Indikace, ze vse probehlo v poradku */ 
}

