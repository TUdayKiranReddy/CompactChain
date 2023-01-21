#!/bin/bash

make

for i in {0..9..1}
	do
		echo $"Iteration $i:-\n"
		./updatetxproof 20000 $i
		echo "\n"
	done

./update_witness_boneh