VERSION := v0.1.3
DATE := $(shell date +"%B %Y")

MANPAGES := kl2tpd.1
MANPAGES += kl2tpd.toml.5
MANPAGES += ql2tpd.1
MANPAGES += ql2tpd.toml.5
MANPAGES += kpppoed.1

.PHONY: default clean

default: $(MANPAGES)

clean:
	rm -f $(MANPAGES)

%.tmp: %.md
	sed 's/_DATE_/$(DATE)/g;s/_VERSION_/$(VERSION)/g' $< > $@

%: %.tmp
	pandoc --standalone --metadata hyphenate=false --from markdown --to man $< | iconv -f utf-8 > $@
