import numpy as np
import matplotlib.pyplot as plt


N = np.array([200, 400, 600, 800, 1000])
cc = np.array([0.159, 0.311, 0.44, 0.58, 0.76])
mc = np.array([0.16, 0.32, 0.43, 0.57, 0.711])
b = np.array([15, 45, 75, 150, 240])

fig, ax = plt.subplots()

ax.plot(N, cc, '-o', color='purple', label='CompactChain')
ax.plot(N, mc, '-^b', label='MiniChain')
ax.set_ylim([0, 5])
plt.legend()

ax2 = ax.twinx()
ax2.plot(N, b, '-*g', label='Boneh')
ax2.set_ylim([0, 300])

plt.legend()
plt.grid()
plt.show()
