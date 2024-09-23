# Název výstupního souboru
TARGET = p2nprobe

# Kompilátor
CC = gcc

# Kompilační volby (např. přidání warningů a optimalizací)
CFLAGS = -Wall -O2

# Závislosti: jaké soubory jsou potřeba pro vytvoření cíle
$(TARGET): p2nprobe.o arg_parser.o exporter.o hash_table.o
	$(CC) $(CFLAGS) -o $(TARGET) p2nprobe.o arg_parser.o exporter.o hash_table.o -lpcap

# Pravidlo pro překlad zdrojového kódu .c na objektový soubor .o
p2nprobe.o: p2nprobe.c
	$(CC) $(CFLAGS) -c p2nprobe.c arg_parser.c exporter.c hash_table.c

# Vyčištění (odstraní objektové a spustitelné soubory)
clean:
	rm -f $(TARGET) p2nprobe.o arg_parser.o exporter.o hash_table.o 
