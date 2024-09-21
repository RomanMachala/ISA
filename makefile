# Název výstupního souboru
TARGET = p2nprobe

# Kompilátor
CC = gcc

# Kompilační volby (např. přidání warningů a optimalizací)
CFLAGS = -Wall -O2

# Závislosti: jaké soubory jsou potřeba pro vytvoření cíle
$(TARGET): p2nprobe.o arg_parser.o
	$(CC) $(CFLAGS) -o $(TARGET) p2nprobe.o arg_parser.o

# Pravidlo pro překlad zdrojového kódu .c na objektový soubor .o
p2nprobe.o: p2nprobe.c
	$(CC) $(CFLAGS) -c p2nprobe.c arg_parser.c

# Vyčištění (odstraní objektové a spustitelné soubory)
clean:
	rm -f $(TARGET) p2nprobe.o
