VERSION := v0.1.5
DATE := $(shell date +"%B %Y")

MANPAGES := kl2tpd.8
MANPAGES += kl2tpd.toml.5
MANPAGES += ql2tpd.8
MANPAGES += ql2tpd.toml.5
MANPAGES += kpppoed.8

.PHONY: default clean

default: $(MANPAGES)

clean:
	rm -f $(MANPAGES)

%.tmp: %.md
	sed 's/_DATE_/$(DATE)/g;s/_VERSION_/$(VERSION)/g' $< > $@

%: %.tmp
	pandoc --standalone --metadata hyphenate=false --from markdown --to man $< | iconv -f utf-8 > $@
