HQC?=../hqc-128

CC=gcc
CFLAGS=-O2 -pedantic -Wall

INCLUDES=-I${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/src/\
			-I${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/lib/fips202

DEPS=${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/src/parameters.h\
		${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/src/api.h\
		${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/src/vector.h\
		${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/src/shake_ds.h\
		${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/src/shake_prng.h\
		${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/src/hqc.h

OBJS=${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/bin/build/kem.o\
		${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/bin/build/hqc.o\
		${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/bin/build/parsing.o\
		${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/bin/build/code.o\
		${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/bin/build/reed_solomon.o\
		${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/bin/build/reed_muller.o\
		${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/bin/build/gf.o\
		${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/bin/build/gf2x.o\
		${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/bin/build/vector.o\
		${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/bin/build/shake_ds.o\
		${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/bin/build/shake_prng.o\
		${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/bin/build/fips202.o\
		${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/bin/build/fft.o\
		${HQC:hqc-128/src hqc-128/lib/fips202=hqc-128}/bin/build/code.o\

all: sample attack

	
sample: sample.o ${OBJS}
	${CC} ${CFLAGS} ${INCLUDES} -o $@ $^ 

sample.o: hqc-128-sample.c ${DEPS}
	${CC} ${CFLAGS} ${INCLUDES} -c $<  -o $@

attack: attack.o ${OBJS}
	${CC} ${CFLAGS} ${INCLUDES} -o $@ $^ 

attack.o: attack.c ${DEPS}
	${CC} ${CFLAGS} ${INCLUDES} -c $<  -o $@

clean:
	rm -f sample.o sample
	rm -f attack.o attack
# clean:
# 	rm -f main.o test-FR.o main test-FR
