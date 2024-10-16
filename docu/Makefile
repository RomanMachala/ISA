TARGET = manual
OUT_DIR = ..

all: $(TARGET).tex $(TARGET).bib
	pdflatex $(TARGET).tex  # První překlad LaTeXu
	bibtex $(TARGET)        # BibTeX pro citace
	pdflatex $(TARGET).tex  # Druhý překlad LaTeXu (citace)
	pdflatex $(TARGET).tex  # Finální překlad
	mv $(TARGET).pdf $(OUT_DIR)  # Přesun PDF do nadřazeného adresáře

# Kompletní vyčištění (odstraní všechny dočasné soubory)
clean:
	rm -f $(TARGET).aux $(TARGET).bbl $(TARGET).blg $(TARGET).log $(TARGET).out $(TARGET).toc

