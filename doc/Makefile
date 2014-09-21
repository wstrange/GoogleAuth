DOCUMENT = totp
DOCUMENT_DEPS = version.texi fdl.texi qr.png
OUT_DIR = out

.PHONY : all
all : doc
.PHONY : doc
doc : info pdf
.PHONY : info
info : $(DOCUMENT).info
.PHONY : pdf
pdf : $(DOCUMENT).pdf

$(DOCUMENT).info : $(DOCUMENT).texi $(DOCUMENT_DEPS)
	makeinfo $(DOCUMENT).texi

$(DOCUMENT).pdf : $(DOCUMENT).texi $(DOCUMENT_DEPS)
	-mkdir $(OUT_DIR)
	( cd $(OUT_DIR) && texi2pdf ../$(DOCUMENT).texi )
	mv $(OUT_DIR)/$(DOCUMENT).pdf .

.PHONY : clean
clean :
	-rm $(DOCUMENT).pdf $(DOCUMENT).info
	-rm -rf $(OUT_DIR)
