import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# os.system("make")
os.chdir(r"/home/solomon/Projects/Blockchain/Scripts/tremel_swarropa_modified/test")
max_trials = 1

u_t_mc = np.zeros(10)
u_t_pr = np.zeros(10)
v_t_mc = np.zeros(10)
v_t_pr = np.zeros(10)
N = np.arange(10)
N = (N+1)*100

for idx in range(max_trials):
	# os.system("./testAccUp " + str(idx))
	accUp = pd.read_csv("testAccUp_result"+str(idx)+".csv") 
	accVer = pd.read_csv("testAccVer_result"+str(idx)+".csv")
	u_t_mc += accUp["Minichain"].to_numpy()
	u_t_pr += accUp["Proposed"].to_numpy()
	v_t_mc += accVer["Minichain"].to_numpy()
	v_t_pr += accVer["Proposed"].to_numpy()
os.chdir(r"/home/solomon/Projects/Blockchain/Scripts/tremel_swarropa_modified/Results")
u_t_mc /= max_trials
u_t_pr /= max_trials
v_t_mc /= max_trials
v_t_pr /= max_trials

# finalUp = pd.DataFrame([N, u_t_mc, u_t_pr], columns=["N", "MiniChain", "Proposed"])
# finalVer = pd.DataFrame([N, v_t_mc, v_t_pr], columns=["N", "MiniChain", "Proposed"])

# finalUp.to_csv("Average_testAccUp"+str(max_trials)+".csv")
# finalVer.to_csv("Average_testAccVer"+str(max_trials)+".csv")
Ac = np.asarray([N, u_t_mc, u_t_pr])
Ver = np.asarray([N, v_t_mc, v_t_pr])
Ac.tofile("FinalAccUp.csv", sep=',', format='%10.5f')
Ver.tofile("FinalAccVer.csv", sep=',', format='%10.5f')

plt.figure()
plt.title("Updation")
plt.plot(N, u_t_mc,  "-*", label="MiniChain")
plt.plot(N, u_t_pr, "-^", label="Proposed")
plt.grid()
plt.legend()
plt.xlabel("Number of transactions")
plt.ylabel("Time taken(in sec)")
plt.savefig("testAccUp.eps")


plt.figure()
plt.title("Verification")
plt.plot(N, v_t_mc, "-^", label="MiniChain")
plt.plot(N, v_t_pr, "-*", label="Proposed")
plt.grid()
plt.legend()
plt.xlabel("Number of transactions")
plt.ylabel("Time taken(in sec)")
plt.savefig("testAccVer.eps")

plt.show()
