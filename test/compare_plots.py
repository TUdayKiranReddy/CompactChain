import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import sys
import os


def compare_plot(argv):
	updates = dict()
	verfication = dict()
	for arg in argv[:-1]:
		df = pd.read_csv("./results/" + arg + "/FinalAccUp.csv")
		df1 = pd.read_csv("./results/" + arg + "/FinalAccVer.csv")
		updates[arg] = np.array([df["N"].to_numpy(), df["Average Time taken"].to_numpy()])
		verfication[arg] = np.array([df1["N"].to_numpy(), df1["Average Time taken"].to_numpy()])

	marker = ["--^", "--o", "--*"]
	i = 0

	plt.figure()
	plt.title("Commitments Update")
	for arg in argv[:-1]:
		print(arg)
		plt.plot(updates[arg][0], updates[arg][1],  marker[i], label=arg[0].upper()+arg[1:])
		i=i+1
	plt.grid()
	plt.legend()
	plt.xlabel("Number of transactions")
	plt.ylabel("Time consumed by a miner (in sec)")
	plt.savefig("testAccUp"+argv[-1]+".eps")


	plt.figure()
	plt.title("NI-PoE proofs for commitments")
	i=0
	for arg in argv[:-1]:
		plt.plot(verfication[arg][0], verfication[arg][1],  marker[i], label=arg[0].upper()+arg[1:])
		i=i+1
	plt.grid()
	plt.legend()
	plt.xlabel("Number of transactions")
	plt.ylabel("Time consumed by a validator (in sec)")
	plt.savefig("testAccVer"+argv[-1]+".eps")

	#plt.show()

if(__name__ == "__main__"):
	compare_plot(sys.argv[1:])