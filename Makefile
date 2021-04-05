BINS	= miner.prg
all:	$(BINS)

miner.prg:	sha2.c sha2.h miner.c
	cl65 -t c64 -Os -Or -Oi sha2.c miner.c -o miner.prg
	md5sum miner.prg > miner.md5

clean:
	rm -f *.o *.s *.prg *.md5

