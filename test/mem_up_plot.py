import numpy as np
import matplotlib.pyplot as plt


N = np.array([200, 400, 600, 800, 1000])
test_cc = np.array([1.31281, 1.20564, 1.19344, 1.2128, 1.14302])
test_mc = np.array([0.852713, 0.905096, 0.875259, 1.02592, 0.87994403])
test_b = np.array([0.216805, 0.428073, 0.809431, 0.8554, 1.50826])

test_cc = np.array([0.94, 0.906, 1.077, 1.315, 1.096])
test_mc = np.array([0.90369, 0.8769, 0.9581, 0.8905, 0.8215])
test_b = np.array([0.266, 0.545, 0.747, 0.97, 1.2873])

test_cc = np.array([0.122897, 0.274156, 0.31194, 0.488942, 0.581113])
test_mc = np.array([0.09487, 0.154933, 0.208161, 0.375824, 0.438553])
test_b = np.array([0.2627, 0.518477, 0.781404, 0.985163, 1.15662])

x = np.arange(len(N))

plt.figure(figsize=(10, 8))
plt.bar(x-0.2, test_b, 0.2, label='Boneh', color='r')
plt.bar(x, test_mc, 0.2, label='MiniChain', color='g')
plt.bar(x+0.2, test_cc, 0.2, label='CompactChain', color='b')
plt.xticks(x, N)
plt.legend(fontsize=15)
plt.xlabel('N', fontsize=15)
plt.ylabel('Time (in s)', fontsize=15)
plt.xticks(fontsize=15)
plt.yticks(fontsize=15)
plt.savefig('MemUpdate.eps')
plt.show()
