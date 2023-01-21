TOPDIR=..

include $(TOPDIR)/rule.mk

BINS=bilinearspeedtest.out rsaspeedtest.out generate_random.out suffixtest.out flinttest.out proposed_algorithm.out testAccUp.out testMerkle.out testproposed.out testboneh.out testminichain.out testMMRTree.out testTXOproof.out testbonehTXO.out testcctxo.out testmctxo.out update_witness_boneh.out testWitUp.out updatetxproof.out libtest.out libtest1.out libdirecttest.out
CFLAGS+=$(DCLXVI_INC) $(CRYPTOPP_INC)
LIBS=$(ACCUMLIB_FLG) $(DCLXVI_LIB_FLG) $(CRYPTOPP_LIB_FLG) $(GMP_LIB_FLG) -lflint -lmpfr
all:	$(BINS)

generate_random: generate_random.o
	$(CPP) $(CFLAGS) -o generate_random generate_random.o $(LIBS)

flinttest: flinttest.o
	$(CPP) $(CFLAGS) -o flinttest flinttest.o $(LIBS)

bilinearspeedtest: bilinearspeedtest.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o bilinearspeedtest.out bilinearspeedtest.o $(LIBS)

rsaspeedtest: rsaspeedtest.o $(ACCUMLIB)
	$(CPP) $(CFLAGS)  -o rsaspeedtest.out rsaspeedtest.o $(LIBS)

suffixtest: suffixtest.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o suffixtest.out suffixtest.o $(LIBS)

libtest: libtest.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o libtest.out libtest.o $(LIBS)

libtest1: libtest1.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o libtest1.out libtest1.o $(LIBS)

libdirecttest: libdirecttest.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o libdirecttest.out libdirecttest.o $(LIBS)

proposed_algorithm: proposed_algorithm.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o proposed_algorithm.out proposed_algorithm.o $(LIBS)

testAccUp: testAccUp.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testAccUp.out testAccUp.o $(LIBS)

testMerkle: testMerkle.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testMerkle.out testMerkle.o $(LIBS)

testproposed: testproposed.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testproposed.out testproposed.o $(LIBS)

testminichain: testminichain.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testminichain.out testminichain.o $(LIBS)

testboneh: testboneh.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testboneh.out testboneh.o $(LIBS)
	
testMMRTree: testMMRTree.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testMMRTree.out testMMRTree.o $(LIBS)

testTXOproof: testTXOproof.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testTXOproof.out testTXOproof.o $(LIBS)

testbonehTXO: testbonehTXO.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testbonehTXO.out testbonehTXO.o $(LIBS)

testcctxo: testcctxo.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testcctxo.out testcctxo.o $(LIBS)

testmctxo: testmctxo.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testmctxo.out testmctxo.o $(LIBS)

update_witness_boneh: update_witness_boneh.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o update_witness_boneh.out update_witness_boneh.o $(LIBS)
	
testWitUp: testWitUp.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testWitUp.out testWitUp.o $(LIBS)

updatetxproof: updatetxproof.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o updatetxproof.out updatetxproof.o $(LIBS)
clean:
	rm -f *.o $(BINS)
