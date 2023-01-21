import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import sys
import os


def average_plot(max_trials, length, step, directory, algo_name):
	os.chdir(directory)

	u_t = np.zeros(length)
	v_t = np.zeros(length)

	N = np.arange(length)
	N = (N+1)*step
	print(os.getcwd())
	for idx in range(max_trials):
		accUp = pd.read_csv("./Data/testAccUp_result"+str(idx)+".csv") 
		accVer = pd.read_csv("./Data/testAccVer_result"+str(idx)+".csv")
		u_t += accUp["Time taken"].to_numpy()
		v_t += accVer["Time taken"].to_numpy()

	u_t /= max_trials
	v_t /= max_trials

	Ac = {"N":N, "Average Time taken":u_t}
	Ver = {"N":N, "Average Time taken":v_t}

	df_Ac = pd.DataFrame(Ac)
	df_Ac.to_csv("FinalAccUp.csv", index=False)
	df_Ver = pd.DataFrame(Ver)
	df_Ver.to_csv("FinalAccVer.csv", index=False)

	plt.figure()
	plt.title("Updation")
	plt.plot(N, u_t,  "-*", label=algo_name)
	plt.grid()
	plt.legend()
	plt.xlabel("Number of transactions")
	plt.ylabel("Time taken(in sec)")
	plt.savefig("testAccUp.eps")


	plt.figure()
	plt.title("Verification")
	plt.plot(N, v_t, "-*", label=algo_name)
	plt.grid()
	plt.legend()
	plt.xlabel("Number of transactions")
	plt.ylabel("Time taken(in sec)")
	plt.savefig("testAccVer.eps")

	#plt.show()

if(__name__ == "__main__"):
	max_trials = 10
	length = 5
	step = 200

	algo_name = sys.argv[1]
	directory = sys.argv[2]
	average_plot(max_trials, length, step, directory, algo_name)
