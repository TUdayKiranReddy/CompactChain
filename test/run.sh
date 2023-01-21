#!/bin/bash

make

echo $"Running simulations for Proposed algorithm......\n"
 for i in {0..9..1}
 	do
 		echo $"Iteration $i:-\n"
 		./testproposed $i
 		echo "\n"
 	done

echo $"Running simulations for Minichain algorithm......\n"
for i in {0..9..1}
	do
		echo $"Iteration $i:-\n"
		./testminichain $i
		echo "\n"
	done

#echo $"Running simulations for Boneh algorithm......\n"
#for i in {0..9..1}
#	do
#		echo $"Iteration $i:-\n"
#		./testboneh $i
#		echo "\n"
#	done

# echo $"Running simulations for Commitment update algorithm......\n"
# for i in {0..49..1}
# 	do
# 		echo $"Iteration $i:-\n"
# 		./testAccUp $i
# 		echo "\n"
# 	done
# python3 average_plot.py Minichain ./results/minichain/
# python3 average_plot.py Proposed ./results/proposed/
python3 average_plot.py Proposed ./results/proposed/
python3 average_plot.py Minichain ./results/minichain/
#python3 average_plot.py Minichain ./results/minichain/
