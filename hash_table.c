/**
 * 
 * @brief Implementace logiky hashovaci tabulky
 * @author Roman Machala (xmacha86)
 * @date 22.09.2024
 * 
 */

#include "hash_table.h"
#include "datagram.h"


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
    hash ^= (flow->prot << 16);

    return hash % MAX_FLOW_LENGTH;
}

/**
 * 
 * @brief funkce porovnavajici polozky 2 toku, volajici musi zajistit, ze ani 1 tok neni NULL
 * 
 * @param first tok 1
 * @param second tok 2
 * 
 * @returns true v pripade shody jinak false
 * 
 */
bool compare_flows(netflowv5 *first, netflowv5 *second){


    return ((first->srcaddr == second->srcaddr && first->dstaddr == second->dstaddr && first->srcport == second->srcport
    && first->dstport == second->dstport && first->prot == second->prot));
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
}

netflowv5 *insert_into_table(netflowv5 **flows, netflowv5 *current_flow){

    int hash = hash_function(current_flow); /* ziska hash */

    /* Pokud zadny zaznam neexistuje, vlozime jej do tabulky */
    if(!flows[hash]){
        flows[hash] = current_flow;
        return flows[hash];
    }

    /* Pokud jiz na danem hashi existuje zaznam, vlozime zaznam na vhodne misto */

    /* zjistime, zdali zaznam jiz v tabulce neni */
    netflowv5 *old_flow = get_flow(flows, current_flow);

    if(old_flow){   /* Pokud zaznam existuje */
        update_flow(old_flow, current_flow);
        free(current_flow);
        current_flow = NULL;
        return old_flow;
    }

    /* pouze pokud na danem hashi jiz neco bylo, najdeme vhodne misto */
    int temp_hash = hash + 1;
    while(temp_hash < MAX_FLOW_LENGTH){

        if(!flows[temp_hash]){
            flows[temp_hash] = current_flow;
            return flows[temp_hash];
        }else if(temp_hash == hash){
            //free(current_flow);
            //current_flow = NULL;
            break;
        }

        temp_hash = (temp_hash + 1) % MAX_FLOW_LENGTH;

    }

    return NULL;
    
}

/**
 * 
 * @brief jednoducha funkce, projde sekvencne celou tabulku a odstrani vsechny zaznamy, pokud nejake zbyly
 * 
 * @param flows hashovaci tabulka obsahujici jendotlive zaznamy
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
 * @brief inicializacni funkce pro hashovaci tabulku, inicializuje tabulku na NULL
 * 
 * @param flows hashovaci tabulka
 * 
 */
void init(netflowv5 **flows){
    for(int i = 0; i < MAX_FLOW_LENGTH; i++){
        flows[i] = NULL;
    }
}

/**
 * 
 * @brief funkce vracejici zaznam o tokuz tabulky
 * 
 * @param flows hashovaci tabulka obsahujici jendotlive zaznamy
 * @param flow tok, jez chceme v taulce vyhledat
 * 
 * @returns nalezeny tok shodny s tokem flow, nebo NULL
 * 
 */
netflowv5 *get_flow(netflowv5 **flows, netflowv5 *flow){
    for(int i = 0; i < MAX_FLOW_LENGTH; i++){
        if(flows[i]){
            if(compare_flows(flows[i], flow)){
                return flows[i];
            }
        }
    }
    return NULL;
}

/**
 * 
 * @brief pomocna funkce pro kopirovani hodnot toku 
 * @param flow1 puvodni tok
 * @param flow2 kopie toku
 * 
 */
void copy_flow(netflowv5 *flow1, netflowv5 *flow2){
    
    flow1->srcaddr      = flow2->srcaddr;       
    flow1->dstaddr      = flow2->dstaddr;       
    flow1->nexthop      = flow2->nexthop;       
    flow1->input        = flow2->input;         
    flow1->output       = flow2->output;         
    flow1->dPkts        = flow2->dPkts;         
    flow1->dOctets      = flow2->dOctets;       
    flow1->first        = flow2->first;         
    flow1->last         = flow2->last;          
    flow1->srcport      = flow2->srcport;       
    flow1->dstport      = flow2->dstport;       
    flow1->pad1         = flow2->pad1;          
    flow1->tcp_flags    = flow2->tcp_flags;     
    flow1->prot         = flow2->prot;          
    flow1->tos          = flow2->tos;           
    flow1->src_as       = flow2->src_as;        
    flow1->dst_as       = flow2->dst_as;        
    flow1->src_mask     = flow2->src_mask;      
    flow1->dst_mask     = flow2->dst_mask;      
    flow1->pad2         = flow2->pad2;     

}

/**
 * 
 * @brief pomocna funkce pro prevod cisla na absolutni hodnotu
 * 
 * @param num cislo, jehoz chceme absolutni hodnotu
 * 
 * @returns absolutni hodnotu cisla
 * 
 */
int abs(int num){
    if(num < 0){
        return -num;
    }
    return num;
}

/**
 * 
 * @brief funkce starajici se o korektni uvolneni toku z tabulky (je zapotrebi, jelikoz se v jednotlivych funkcich pracuje s lokalni promennou
 *        tudiz nelze potom nastavit ukazatel v tabulce na NULL - prisel jsem na toto v pozdejsi fazi vyvoje, musel bych prepisovat polovinu kodu)
 * 
 * @param flows hashovaci tabulka uchovavajici vsechny zaznamy o jednotlivych tocich
 * @param flow tok, jez ma byt z tabulky uvolnen
 * 
 */
void free_flow(netflowv5 **flows, netflowv5 *flow){
    /* Projde sekvencne celou tabulku */
    for (int i = 0; i < MAX_FLOW_LENGTH; i++){
        if(flows[i]){
            if(compare_flows(flows[i], flow)){
                /* Pokud se jedna o stejny tok, uvolni jej */
                free(flows[i]);
                flows[i] = NULL;
            }
        }
    }
}


