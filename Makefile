LIBRARIES = -lcrypto

all: x25519-alice x25519-bob

x25519-alice: x25519-alice.c
	gcc x25519-alice.c $(LIBRARIES) -o x25519-alice

x25519-bob: x25519-bob.c
	gcc x25519-bob.c $(LIBRARIES) -o x25519-bob
