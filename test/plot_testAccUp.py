import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

os.system("make")

max_trials = 10
length = 5
step = 200

u_t_mc = np.zeros(length)
u_t_pr = np.zeros(length)
v_t_mc = np.zeros(length)
v_t_pr = np.zeros(length)
N = np.arange(length)
N = (N+1)*step

for idx in range(max_trials):
	os.system("./testAccUp " + str(idx))
	accUp = pd.read_csv("testAccUp_result"+str(idx)+".csv") 
	accVer = pd.read_csv("testAccVer_result"+str(idx)+".csv")
	u_t_mc += accUp["Minichain"].to_numpy()
	u_t_pr += accUp["Proposed"].to_numpy()
	v_t_mc += accVer["Minichain"].to_numpy()
	v_t_pr += accVer["Proposed"].to_numpy()

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
plt.plot(N, v_t_mc, "-*", label="MiniChain")
plt.plot(N, v_t_pr, "-^", label="Proposed")
plt.grid()
plt.legend()
plt.xlabel("Number of transactions")
plt.ylabel("Time taken(in sec)")
plt.savefig("testAccVer.eps")

plt.show()
