THISDIR = $(shell pwd)

all: 

clean:
	rm -rf $(SRC_NAME)
	rm -f AdGuardHome

romfs:
	$(ROMFSINST) -p +x $(THISDIR)/adguardhome.sh /usr/bin/adguardhome.sh