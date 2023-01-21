TOPDIR=..

include $(TOPDIR)/rule.mk

BINS=bilinearspeedtest.out rsaspeedtest.out generate_random.out suffixtest.out flinttest.out proposed_algorithm.out testAccUp.out testMerkle.out testproposed.out testboneh.out testminichain.out testMMRTree.out testTXOproof.out testbonehTXO.out testcctxo.out testmctxo.out update_witness_boneh.out testWitUp.out updatetxproof.out libtest.out libtest1.out libdirecttest.out
CFLAGS+=$(DCLXVI_INC) $(CRYPTOPP_INC)
LIBS=$(ACCUMLIB_FLG) $(DCLXVI_LIB_FLG) $(CRYPTOPP_LIB_FLG) $(GMP_LIB_FLG) -lflint -lmpfr
all:	$(BINS)

generate_random.out: generate_random.o
	$(CPP) $(CFLAGS) -o generate_random generate_random.o $(LIBS)

flinttest.out: flinttest.o
	$(CPP) $(CFLAGS) -o flinttest.out flinttest.o $(LIBS)

bilinearspeedtest.out: bilinearspeedtest.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o bilinearspeedtest.out bilinearspeedtest.o $(LIBS)

rsaspeedtest.out: rsaspeedtest.o $(ACCUMLIB)
	$(CPP) $(CFLAGS)  -o rsaspeedtest.out rsaspeedtest.o $(LIBS)

suffixtest.out: suffixtest.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o suffixtest.out suffixtest.o $(LIBS)

libtest.out: libtest.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o libtest.out libtest.o $(LIBS)

libtest1.out: libtest1.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o libtest1.out libtest1.o $(LIBS)

libdirecttest.out: libdirecttest.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o libdirecttest.out libdirecttest.o $(LIBS)

proposed_algorithm.out: proposed_algorithm.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o proposed_algorithm.out proposed_algorithm.o $(LIBS)

testAccUp.out: testAccUp.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testAccUp.out testAccUp.o $(LIBS)

testMerkle.out: testMerkle.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testMerkle.out testMerkle.o $(LIBS)

testproposed.out: testproposed.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testproposed.out testproposed.o $(LIBS)

testminichain.out: testminichain.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testminichain.out testminichain.o $(LIBS)

testboneh.out: testboneh.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testboneh.out testboneh.o $(LIBS)
	
testMMRTree.out: testMMRTree.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testMMRTree.out testMMRTree.o $(LIBS)

testTXOproof.out: testTXOproof.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testTXOproof.out testTXOproof.o $(LIBS)

testbonehTXO.out: testbonehTXO.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testbonehTXO.out testbonehTXO.o $(LIBS)

testcctxo.out: testcctxo.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testcctxo.out testcctxo.o $(LIBS)

testmctxo.out: testmctxo.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testmctxo.out testmctxo.o $(LIBS)

update_witness_boneh.out: update_witness_boneh.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o update_witness_boneh.out update_witness_boneh.o $(LIBS)
	
testWitUp.out: testWitUp.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o testWitUp.out testWitUp.o $(LIBS)

updatetxproof.out: updatetxproof.o $(ACCUMLIB)
	$(CPP) $(CFLAGS) -o updatetxproof.out updatetxproof.o $(LIBS)
clean:
	rm -f *.o $(BINS)
