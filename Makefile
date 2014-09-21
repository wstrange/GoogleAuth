.PHONY : all
all : doc
.PHONY : doc
doc :
	$(MAKE) -wC doc doc

.PHONY : clean
clean :
	$(MAKE) -wC doc clean
