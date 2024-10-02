# Nazev vystupniho souboru
TARGET = p2nprobe
CO=manual

# Compiler
CC = gcc

# kompilacni volby
CFLAGS = -Wall -O2

# Závislosti: jaké soubory jsou potřeba pro vytvoření cíle
$(TARGET): p2nprobe.o arg_parser.o exporter.o hash_table.o datagram.o
	$(CC) $(CFLAGS) -o $(TARGET) p2nprobe.o arg_parser.o exporter.o hash_table.o datagram.o -lpcap

# preklad
p2nprobe.o: p2nprobe.c
	$(CC) $(CFLAGS) -c p2nprobe.c arg_parser.c exporter.c hash_table.c datagram.c

# Vyčištění (odstraní objektové a spustitelné soubory)
clean:
	rm -f $(TARGET) p2nprobe.o arg_parser.o exporter.o hash_table.o datagram.o

tex: $(CO).tex $(CO).bib
	pdflatex $(CO).tex  # První překlad LaTeXu
	bibtex $(CO)        # BibTeX pro citace
	pdflatex $(CO).tex  # Druhý překlad LaTeXu (citace)
	pdflatex $(CO).tex  # Finální překlad

# Kompletní vyčištění (odstraní všechny dočasné soubory)
clean_tex:
	rm -f $(CO).pdf $(CO).aux $(CO).bbl $(CO).blg $(CO).log