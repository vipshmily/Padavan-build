THISDIR = $(shell pwd)
xray_dir="xray.com/core/main"
export GO111MODULE=on
export GOPROXY=https://goproxy.io
Xray_VERSION := 1.5.3
Xray_URL := https://codeload.github.com/XTLS/Xray-core/tar.gz/v$(Xray_VERSION)
XRAY_SED_ARGS:=
XRAY_SED_ARGS += \
	s/_ "xray.com\/core\/main\/json"/\/\/ &/; \
	/\/\/ _ "xray.com\/core\/main\/jsonem"/s/\/\/ //;
XRAY_SED_ARGS += \
	s/_ "xray.com\/core\/main\/json"/\/\/ &/;

#all:download_xray build_extract build_xray
all:download_xray 

download_xray:
	( if [ ! -f $(THISDIR)/xray-core-$(Xray_VERSION).tar.gz ]; then \
	curl --create-dirs -L $(Xray_URL) -o $(THISDIR)/xray-core-$(Xray_VERSION).tar.gz ; \
	fi )

build_extract:
	mkdir -p $(THISDIR)/xray.com
	mkdir -p $(THISDIR)/bin
	( if [ ! -d $(THISDIR)/xray.com/core ]; then \
	tar zxfv $(THISDIR)/xray-core-$(Xray_VERSION).tar.gz -C $(THISDIR)/xray.com ; \
	mv $(THISDIR)/xray.com/xray-core-$(Xray_VERSION) $(THISDIR)/xray.com/core ; \
	fi )

build_xray:
	( cd $(THISDIR)/$(xray_dir); \
	sed -i \
			'$(XRAY_SED_ARGS)' \
			distro/all/all.go ; \
	GOOS=linux GOARCH=mipsle go build -ldflags "-w -s" -o $(THISDIR)/bin/xray; \
	)

clean:
	#rm -rf $(THISDIR)/xray.com
	#rm -rf $(THISDIR)/bin

romfs:
	$(ROMFSINST) -p +x $(THISDIR)/bin/xray /usr/bin/v2ray
