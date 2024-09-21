/**
 *
 * @author Roman Machala
 * @date 21.09.2024
 *
 *   
 */ 

#include "arg_parser.h"

int main(int argc, char *argv[]){

    arguments args;
    parse_arguments(&args, argv, argc);
    return 0;
}