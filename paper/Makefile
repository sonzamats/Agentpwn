TEX     = pdflatex
BIB     = bibtex
MAIN    = agentpwn
FLAGS   = -interaction=nonstopmode -halt-on-error

.PHONY: all clean

all: $(MAIN).pdf

$(MAIN).pdf: $(MAIN).tex references.bib
	$(TEX) $(FLAGS) $(MAIN)
	$(BIB) $(MAIN)
	$(TEX) $(FLAGS) $(MAIN)
	$(TEX) $(FLAGS) $(MAIN)

clean:
	rm -f $(MAIN).aux $(MAIN).bbl $(MAIN).blg $(MAIN).log \
	      $(MAIN).out $(MAIN).toc $(MAIN).pdf $(MAIN).nav \
	      $(MAIN).snm $(MAIN).fdb_latexmk $(MAIN).fls \
	      $(MAIN).synctex.gz
