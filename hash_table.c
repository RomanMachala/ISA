/**
 * 
 * @brief Implementace logiky hashovaci tabulky
 * @author Roman Machala
 * @date 22.09.2024
 * 
 */

#include "hash_table.h"


/**
 *
 * @brief hashovaci funkce pro hashovaci tabulku
 * 
 * @param flow aktualne zpracovavany tok
 * 
 * @returns hash index
 * 
 */
int hash_function(netflowv5 *flow){
    uint64_t hash = flow->srcaddr;
    hash ^= flow->dstaddr;
    hash ^= (flow->srcport << 16);
    hash ^= (flow->dstport << 16);
    hash ^= (flow->tos < 24);
    hash ^= (flow->input << 8);

    return hash % MAX_FLOW_LENGTH;
}

/**
 * 
 * @brief funkce porovnavajici polozky 2 toku
 * 
 * @param first tok 1
 * @param second tok 2
 * 
 * @returns true v pripade shody jinak false
 * 
 */
bool compare_flows(netflowv5 *first, netflowv5 *second){
    /* Porovnava pouze informace, ktere jsou potreba pro identifikaci toku, vice v hlavickovem souboru */
    return (first->srcaddr == second->srcaddr && first->dstaddr == second->dstaddr && first->srcport == second->srcport
    && first->dstport == second->dstport && first->tos == second->tos && first->input == second->input);
}

/**
 * 
 * @brief funkce aktualizujici zaznam v tabulce, pokud se jedna o stejny tok, pricteme nove hodnoty ke stavajicim
 * 
 */
void update_flow(netflowv5 *first, netflowv5 *second){
    /* navysi se pocet paketu (ekvivalentni += 1) */
    first->dPkts += second->dPkts;
    
    /* Zvyseni poctu bajtu */
    first->dOctets += second->dOctets;
    
    /* Cas posledniho prijateho paketu */
    first->last = second->last;
    
    /* OR operace nad TCP flagy */
    first->tcp_flags |= second->tcp_flags;

    /* Jine zaznamy o toku jsou nemenne (srcaddr, dstaddr, ...) */
    /* free(second); */ /* Uvolnime pamet pro druhy tok, protoze doslo ke jejich slouzeni */
}

netflowv5 *insert_into_table(netflowv5 **flows, netflowv5 *current_flow){
    int hash = hash_function(current_flow);

    /* Pokud zaznam jeste neexistuje */
    if(!flows[hash]){
        /* Vlozime jej do tabulky */
        flows[hash] = current_flow;
        return flows[hash];
    }

    /* Pokud zaznam jiz existuje, zkontrolujeme, zda se jedna o stejny zaznam nebo doslo ke kolizi hashu */
    while(hash < MAX_FLOW_LENGTH){
        /* Pokud jiz jsme narazili na volny zaznam nebo na stejnou polozku ukoncime prochazeni */
        if(!flows[hash] || compare_flows(flows[hash], current_flow)) break;
        hash = (hash + 1) % MAX_FLOW_LENGTH;    /* Inkrementace hashe pro posun na dalsi polozku */
    }

    if(!flows[hash]){
        flows[hash] = current_flow;    /* Vlozime novy tok na nejblizsi volne misto */
    }else{
        update_flow(flows[hash], current_flow);
    }

    return flows[hash];
}

/**
 * 
 * @brief jednoducha funkce, projde sekvencne celou tabulku a odstrani vsechny zaznamy, pokud nejake zbyly
 * 
 */
void clean_flows(netflowv5 **flows){
    for(int i = 0; i < MAX_FLOW_LENGTH; i++){
        if(flows[i]){ 
            free(flows[i]);
            flows[i] = NULL;
        }
    }
}

/**
 *
 * @brief debugovaci funkce pro zobrazeni jednotlivych toku
 * 
 * @param flows hashovaci tabulka obsahujici jednotlive zaznamy o vsech tocich
 * 
 */ 
void print_flows(netflowv5 **flows){
    int counter = 1;
    /* projdeme vsechny polozky v tabulce sekvencne */
    for(int i = 0; i < MAX_FLOW_LENGTH; i++){
        /* Pokud zaznam existuje */
        if(flows[i]){
            printf("Flow n.%d\n", counter++);

            char IP[INET_ADDRSTRLEN];

            struct in_addr addr;
            addr.s_addr = htonl(flows[i]->srcaddr);
            inet_ntop(AF_INET, &addr, IP, sizeof(IP));
            printf("\tSrcIP addr:\t\t\t%s\n", IP);
            addr.s_addr = htonl(flows[i]->dstaddr);
            inet_ntop(AF_INET, &addr, IP, sizeof(IP));
            printf("\tDstIP addr:\t\t\t%s\n", IP);
        }
    }
}

void init(netflowv5 **flows){
    for(int i = 0; i < MAX_FLOW_LENGTH; i++){
        flows[i] = NULL;
    }
}

netflowv5 *get_flow(netflowv5 **flows, netflowv5 *flow){
    int hash = hash_function(flow);

    while(hash < MAX_FLOW_LENGTH){
        if(compare_flows(flows[hash], flow)) return flows[hash];

        hash = (hash + 1) % MAX_FLOW_LENGTH;
    }

    return NULL;
}



