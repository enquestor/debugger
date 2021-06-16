.PHONY: clean pack

CPP = g++
CPPFLAGS = -g -Wall -std=c++17
LIBS = -lcapstone
PROGNAME = sdb
ZIPNAME = 0713407_hw4

all: $(PROGNAME)

$(PROGNAME): $(PROGNAME).cpp
	$(CPP) -o $@ $(CPPFLAGS) $^ $(LIBS)

clean:
	rm -rf $(PROGNAME)

pack: clean
	mkdir ~/$(ZIPNAME)
	cp -r * ~/$(ZIPNAME)
	mv ~/$(ZIPNAME) .
	zip -r $(ZIPNAME) $(ZIPNAME) -x ".git*" -x ".DS_Store"
	rm -rf $(ZIPNAME)
