#!/bin/bash

REF_OUTPUT_DIR="output/ref/"        #vystup referencniho nastroje softflowd
PROG_OUTPUT_DIR="output/prog/"      #vystup implementovaneho exporteru

TEST_FILE_DIR="test_files/"         #umisteni testovacich pcap souboru

PROGRAM="../p2nprobe"               #umisteni a nazev exporteru

FILTERED_FILE="filtered"

VALGRIND_TEST="./test_valgrind.sh"


RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'


# funkce pro extrakci jednotlivych polozek
extract_metrics() {
    local output="$1"
    local output_2="$2"
    flows=$(echo "$output" | grep -oP 'total flows:\s*\K\d+')
    bytes=$(echo "$output" | grep -oP 'total bytes:\s*\K\d+')
    packets=$(echo "$output" | grep -oP 'total packets:\s*\K\d+')
    avg_bps=$(echo "$output" | grep -oP 'avg bps:\s*\K\d+')
    avg_pps=$(echo "$output" | grep -oP 'avg pps:\s*\K\d+')
    avg_bpp=$(echo "$output" | grep -oP 'avg bpp:\s*\K\d+')
    flows_processed=$(echo "$output_2" | grep -oP 'Total flows processed:\s*\K\d+')
    block_skipped=$(echo "$output_2" | grep -oP 'Blocks skipped: \s*\K\d+')
    bytes_read=$(echo "$output_2" | grep -oP 'Bytes read: \s*\K\d+')
}

# funkce pro extrakci casu
extract_times() {
    local time_window="$1"
    if [[ $time_window =~ ([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2})\ -\ ([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}) ]]; then
        echo "${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"
    else
        echo ""
    fi
}

echo -e "${BLUE}Running collector and exporters!${NC}"
echo ""
echo ""


for test_file in "$TEST_FILE_DIR"*; do
    if [ -f "$test_file" ]; then

    # zpracovavame pouze tcp pakety
    tcpdump -r "$test_file" -w "$FILTERED_FILE" -p tcp > /dev/null 2>&1

    # spusti kolektor pro referenccni nastroj
    nohup nfcapd -l "$REF_OUTPUT_DIR" -p 1010 > /dev/null 2>&1 &

    NETFLOW_PID=$!

    sleep 1
    # spusti referencni nastroj
    softflowd -r "$FILTERED_FILE" -n localhost:1010 -v 5 -d > /dev/null 2>&1

    kill $NETFLOW_PID
    wait $NETFLOW_PID

    rm "$FILTERED_FILE"
    #ukonci kolektor

    #spusti kolektor pro implementovany exporter
    nohup nfcapd -l "$PROG_OUTPUT_DIR" -p 1020 > /dev/null 2>&1 &

    NETFLOW_PID=$!

    sleep 1
    #spusti implementovany exporter
    "$PROGRAM" localhost:1020 "$test_file" 2>&1


    #ukonci exporter
    kill $NETFLOW_PID
    wait $NETFLOW_PID

        # tato cast prejmenuje vystupy kolektoru na nazev odpovidajici testovacimu souboru .pcap
        FILE=$(ls "$REF_OUTPUT_DIR"nfcapd* 2>/dev/null | head -n 1)

        filename=$(basename "$test_file")

        basename="${filename%.*}"

        if [ -z "$FILE" ]; then
            echo "No such file!"
        else
            mv "$FILE" "$REF_OUTPUT_DIR""$basename"
        fi

        FILE=$(ls "$PROG_OUTPUT_DIR"nfcapd* 2>/dev/null | head -n 1)

        if [ -z "$FILE" ]; then
            echo "No such file!"
        else
            mv "$FILE" "$PROG_OUTPUT_DIR""$basename"
        fi
    fi




done

total_tests=0
    failed=0

    echo ""
    echo ""
    #projedeme vsechny vystupy a porovname je mezi sebou
    for output_file in "$REF_OUTPUT_DIR"/*; do
        ((total_tests++))
    
        filename=$(basename "$output_file") #ziskame nazev souboru

        ref_output=$(nfdump -r "$REF_OUTPUT_DIR""$filename")
        prog_output=$(nfdump -r "$PROG_OUTPUT_DIR""$filename")
        #ziskame nfdump vystup


        REF_TOTAL_SUMMARY=$(echo "$ref_output" | grep total)
        PROG_TOTAL_SUMMARY=$(echo "$prog_output" | grep total)

        REF_TIME_WINDOW=$(echo "$ref_output" | grep Time)
        PROG_TIME_WINDOW=$(echo "$prog_output" | grep Time)

        REF_TOTAL=$(echo "$ref_output" | grep Total)
        PROG_TOTAL=$(echo "$prog_output" | grep Total)


        # Extrahujeme hodnoty z referenčního výstupu
        extract_metrics "$REF_TOTAL_SUMMARY" "$REF_TOTAL"
        ref_flows=$flows
        ref_bytes=$bytes
        ref_packets=$packets
        ref_avg_bps=$avg_bps
        ref_avg_pps=$avg_pps
        ref_avg_bpp=$avg_bpp
        ref_processed=$flows_processed
        ref_skipped=$block_skipped
        ref_read=$bytes_read

        # Extrahujeme hodnoty z implementovaného výstupu
        extract_metrics "$PROG_TOTAL_SUMMARY" "$PROG_TOTAL"
        impl_flows=$flows
        impl_bytes=$bytes
        impl_packets=$packets
        impl_avg_bps=$avg_bps
        impl_avg_pps=$avg_pps
        impl_avg_bpp=$avg_bpp
        impl_processed=$flows_processed
        impl_skipped=$block_skipped
        impl_read=$bytes_read

        ref_times=$(extract_times "$REF_TIME_WINDOW")
        impl_times=$(extract_times "$PROG_TIME_WINDOW")

        read ref_start ref_end <<< "$ref_times"
        read impl_start impl_end <<< "$impl_times"

        error_count=0
        echo -e "${BLUE}Running results for test $filename${NC}:"


        if [ "$ref_flows" -ne "$impl_flows" ]; then
            ((error_count++))
            echo -e "${RED}Number of flows doesn't match${NC} - REF: $ref_flows / IMPL: $impl_flows"
        fi
        if [ "$ref_bytes" -ne "$impl_bytes" ]; then
            ((error_count++))
            echo -e "${RED}Bytes count doesn't match${NC} - REF: $ref_bytes / IMPL: $impl_bytes"
        fi
        if [ "$ref_packets" -ne "$impl_packets" ]; then
            ((error_count++))
            echo -e "${RED}Number of packets doesn't match${NC} - REF: $ref_packets / IMPL: $impl_packets"
        fi
        if [ "$ref_avg_bps" -ne "$impl_avg_bps" ]; then
            echo -e "${YELLOW}Avg bps doesn't match${NC} - REF: $ref_avg_bps / IMPL: $impl_avg_bps"
        fi
        if [ "$ref_avg_pps" -ne "$impl_avg_pps" ]; then
            echo -e "${YELLOW}Avg pps doesn't match${NC} - REF: $ref_avg_pps / IMPL: $impl_avg_pps"
        fi
        if [ "$ref_avg_bpp" -ne "$impl_avg_bpp" ];then
            echo -e "${YELLOW}Avg bpp doesn't match${NC} - REF: $ref_avg_bpp / IMPL: $impl_avg_bpp"
        fi
        if [ "$ref_processed" -ne "$impl_processed" ]; then
            ((error_count++))
            echo -e "${RED}Num of processed flows doesn't match${NC} - REF: $ref_processed / IMPL: $impl_processed"
        fi
        if [ "$ref_skipped" -ne "$impl_skipped" ]; then
            ((error_count++))
            echo -e "${RED}Num of blocks skipped doesn't match${NC} - REF: $ref_skipped / IMPL: $impl_skipped"
        fi
        if [ "$ref_read" -ne "$impl_read" ]; then
            ((error_count++))
            echo -e "${RED}Num of bytes read doesn't match${NC} - REF: $ref_read / IMPL: $impl_read"
        fi

        if [[ "$ref_start" != "$impl_start" ]]; then
            ((error_count++))
            echo -e "${RED}Time window start doesn't match${NC} - REF: $ref_start / IMPL: $impl_start"
        fi
        if [[ "$ref_end" != "$impl_end" ]]; then
            ((error_count++))
            echo -e "${RED}Time window end doesn't match${NC} - REF: $ref_end / IMPL: $impl_end"
        fi

        if [ "$error_count" -eq 0 ]; then
            echo -e "${GREEN}TEST PASSED${NC}"
        else
            echo -e "${RED}TEST FAILED${NC}"
            ((failed++))
        fi
        echo ""
        echo ""
    done


    echo -e "${RED}FAILED TESTS: $failed${NC}/$total_tests"


    #spusti valgrind testy

    "$VALGRIND_TEST"




