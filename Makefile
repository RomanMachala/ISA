# Nazev vystupniho souboru
TARGET = p2nprobe


# Compiler
CC = gcc

# kompilacni volby
CFLAGS = -Wall -O2

# Závislosti: jaké soubory jsou potřeba pro vytvoření cíle
$(TARGET): p2nprobe.o arg_parser.o exporter.o hash_table.o datagram.o
	$(CC) $(CFLAGS) -o $(TARGET) p2nprobe.o arg_parser.o exporter.o hash_table.o datagram.o -lpcap -lrt

# preklad
p2nprobe.o: p2nprobe.c
	$(CC) $(CFLAGS) -c p2nprobe.c arg_parser.c exporter.c hash_table.c datagram.c

# Vyčištění (odstraní objektové a spustitelné soubory)
clean:
	rm -f $(TARGET) p2nprobe.o arg_parser.o exporter.o hash_table.o datagram.o
