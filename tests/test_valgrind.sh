#!/bin/bash

TEST_FOLDER="test_files/"
PROGRAM="../p2nprobe"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'

extract_valgrind_metrics() {
    local output="$1"
    
    total_allocs=$(echo "$output" | grep -oP 'total heap usage: \d+ allocs' | grep -oP '\d+')
    total_frees=$(echo "$output" | grep -oP '\d+ frees' | grep -oP '\d+')
    in_use=$(echo "$output" | grep -oP 'in use at exit:\s*\K\d+ bytes')
    definitely_lost=$(echo "$output" | grep -oP 'definitely lost:\s*\K\d+ bytes')
    indirectly_lost=$(echo "$output" | grep -oP 'indirectly lost:\s*\K\d+ bytes')
    possibly_lost=$(echo "$output" | grep -oP 'possibly lost:\s*\K\d+ bytes')
    still_reachable=$(echo "$output" | grep -oP 'still reachable:\s*\K\d+ bytes')
}

valgrind_count=0
total_tests=0

for test_file in "$TEST_FOLDER"*; do
    if [ -f "$test_file" ]; then
        ((total_tests++))

        echo -e "${BLUE}Running valgrind test for $test_file${NC}"

        #run program
        valgrind_output=$(valgrind --leak-check=full "$PROGRAM" "localhost:1010" "$test_file" 2>&1)
        extract_valgrind_metrics "$valgrind_output"
        in_use=$(echo "$in_use" | sed 's/ bytes//')
        definitely_lost=$(echo "$definitely_lost" | sed 's/ bytes//')
        indirectly_lost=$(echo "$indirectly_lost" | sed 's/ bytes//')
        possibly_lost=$(echo "$possibly_lost" | sed 's/ bytes//')
        still_reachable=$(echo "$still_reachable" | sed 's/ bytes//')

        if [ "$total_allocs" -ne "$total_frees" ]; then
            ((valgrind_count++))
            echo -e "${YELLOW}Total allocs doesn't match total frees!${NC} - $total_allocs / $total_frees"
        fi
        if [ "$in_use" -ne 0 ]; then
            ((valgrind_count++))
            echo -e "${YELLOW}Bytes still in use is not zero!${NC} - $in_use"
        fi
        if [ -n "$definitely_lost" ]; then
            ((valgrind_count++))
            echo -e "${YELLOW}Definitely lost bytes is not zero!${NC} - $definitely_lost"
        fi
        if [ -n "$indirectly_lost" ]; then
            ((valgrind_count++))
            echo -e "${YELLOW}indirectly lost bytes is not zero!${NC} - $indirectly_lost"
        fi
        if [ -n "$possibly_lost" ]; then
            ((valgrind_count++))
            echo -e "${YELLOW}Possibly lost is not zero!${NC} - $possibly_lost"
        fi
        if [ -n "$still_reachable" ]; then
            ((valgrind_count++))
            echo -e "${YELLOW}Still reachable bytes is not zero!${NC} - $still_reachable"
        fi

        if [ "$valgrind_count" -ne 0 ]; then
            echo -e "${RED}Valgrind failed for test $test_file ${NC}"
        fi


    fi

done

echo -e "${RED}Failed valgrind tests $valgrind_count / $total_tests${NC}"