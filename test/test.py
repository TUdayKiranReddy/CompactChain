import numpy as np

def f(x):
	h = np.ceil(np.log2(x))
	return h, (2**(h+1)) - 1

print(f(129))