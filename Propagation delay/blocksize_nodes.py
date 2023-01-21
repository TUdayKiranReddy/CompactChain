import os
import sys
import numpy as np
import pylab
from heapq import *

from btcsim import *

# size definitions used for blocksize, link- and validation-speed
KiloByte = 1024
MegaByte = 1024*KiloByte
GigaByte = 1024*MegaByte

# number of total nodes in the bitcoin network
n = 10000
t = 0.0
event_q = []

# root block
seed_block = Block(None, 0, t, -1, 0, 1)


# set up some miners with random hashrate
#numminers = 12
#hashrates = numpy.random.exponential(1.0, numminers)
#hashrates = numpy.array([167,137,85,76,69,42,39,19,16,14,11,11,8,5,3])

hashrates = np.zeros(n)
miner_hashrates = numpy.array([133,87,84,84,72,65,59,58,35,12,9,1,1])
numminers = len(hashrates)
miner_hashrates = miner_hashrates/miner_hashrates.sum()
#print(miner_hashrates)
#print(len(miner_hashrates))

for i in range(n):
	if i < len(miner_hashrates):
		hashrates[i] = miner_hashrates[i]
	else:
		hashrates[i] = 0.0 
hash_rate = numpy.array(hashrates)
#print(len(hashrates))
#print(hashrates)


maxdays = 365*24*60*60
blocksize = 1.034*MegaByte
validationrate = 1.95*MegaByte # per s



latency = 0.030 # in s, aka ~6000km with speed of light
bandwidth = 1*MegaByte # per s, combined available to each node
network = 'all'

miners = []
print(numminers)
for i in range(numminers):
	#miners.append(Miner(i, hashrates[i] * 1.0*(1-numpy.max(hashrates))/(numpy.max(hashrates)*20.0), validationrate, blocksize, seed_block, event_q, t))
	miners.append(Miner(i, hashrates[i] * 1.0/600.0, validationrate, blocksize, seed_block, event_q, t))

links = []
# add some random links to each miner
for i in range(numminers):
	for k in range(4):
		j = numpy.random.randint(0,numminers)
		if (i != j and (i,j) not in links):
			miners[i].add_link(j,latency,bandwidth)
			links.append((i,j))
		if (j != i and (j,i) not in links):
			miners[j].add_link(i,latency,bandwidth)
			links.append((j,i))



# simulate some days of block generation
curday = 0
#maxdays = 5*7*24*60*60
maxdays = 0.01*24*60*60

while t < maxdays:
    t, t_event = heappop(event_q)
    #print('##################################################################################')
    #print('%08.3f: %02d->%02d %s' % (t, t_event.orig, t_event.dest, t_event.action), t_event.payload)
    miners[t_event.dest].receive_event(t, t_event)
    #print('##################################################################################')
    if t/(24*60*60) > curday:
        print('day %03d' % curday)
        curday = int(t/(24*60*60))+1

#print('number of events %d' %i)
#print('Number of blocks added to miner 0 : %d' %(len(miners[0].blocks)))

# data analysis

pylab.figure()

cols = ['r-', 'g-', 'b-', 'y-']


# #for i in range(numminers):
	# #mine = miners[i]
	# #t_hash = mine.chain_head
	# #print('Hash of the block with highest block height with miner %d : %s' %(i,t_hash))
	# #print('Number of blocks added to miner %d: %d' %(i,len(mine.blocks)))
	# #numblocks = 0
	# #while t_hash != None :
		# #t_block = mine.blocks[t_hash]
		# ##if t_block.prev != None:
			# ##pylab.plot([mine.blocks[t_block.prev].time, t_block.time], [mine.blocks[t_block.prev].height, t_block.height])
		# #t_hash = t_block.prev
		# #numblocks += 1
	# #print('Number of blocks at miner %d : %d' %(i,numblocks))


# mine = miners[0]
# t_hash = mine.chain_head
# print('Average block height time: %0.3f min' % (mine.blocks[mine.chain_head].time/(60*mine.blocks[mine.chain_head].height)))
# beta = mine.blocks[mine.chain_head].time/(mine.blocks[mine.chain_head].height)
# print('Main chain growth rate: %0.3f' %(1.0/beta))

# rewardsum = 0.0
# for i in range(numminers):
	# miners[i].reward = 0.0

# main_chain = dict()
# main_chain[hash(seed_block)] = 1

# while t_hash != None:
	# t_block = mine.blocks[t_hash]
	# if (t_hash not in main_chain):
		# main_chain[t_hash] = 1
	
	# miners[t_block.miner_id].reward += 1
	# rewardsum += 1
	
	# if t_block.prev != None:
		# pylab.plot([mine.blocks[t_block.prev].time, t_block.time], [mine.blocks[t_block.prev].height, t_block.height], cols[t_block.miner_id%4])
	
	# t_hash = t_block.prev

# pylab.xlabel('time in s')
# pylab.ylabel('block height')
# pylab.grid()
# pylab.legend()
# #pylab.savefig('./figs/block_time_height_bitcoin_7_100_nodes.eps')
# pylab.draw()

# pylab.figure()
# print([0, np.max(hashrates)*1.05])
# pylab.plot([0, np.max(hashrates)*1.05], [0, np.max(hashrates)*1.05],color='0.4', label = 'Expected')
# print(rewardsum)

# rewards = np.array(np.zeros(len(miner_hashrates)))
# for i in range(len(rewards)):
	# print('Rewards of miner %d : %d' %(i,miners[i].reward))
	# print('%2d: %0.3f -> %0.3f : %0.1f%%' % (i, hashrates[i], miners[i].reward/rewardsum, (miners[i].reward/(rewardsum*hashrates[i]) - 1.0)*100))
	# #pylab.plot(hashrates[i], miners[i].reward/rewardsum, 'k.',color = 'r')
	# #pylab.plot(hashrates[i], miners[i].reward/rewardsum, 'rx')
	# rewards[i] = miners[i].reward/rewardsum

# pylab.plot(hashrates[0:13],rewards[0:13], 'k.',color = 'r',label = 'Simulation')
	
# pylab.xlabel('Fraction of Hashrates')
# pylab.ylabel('Fraction of rewards')
# pylab.grid()
# pylab.legend(loc = 2)
# #pylab.savefig('./figs/Hashrate_reward_bitcoin_7_100_nodes.eps')
# pylab.draw()


# #pylab.figure()
# #orphans = 0
# #for i in range(numminers):
	# #for t_hash in miners[i].blocks:
		# #if t_hash not in main_chain:
			# #orphans += 1
		
		# # draws the chains
		# #if miners[i].blocks[t_hash].height > 1:
			# #cur_b = miners[i].blocks[t_hash]
			# #pre_b = miners[i].blocks[cur_b.prev]
			# ##pylab.plot([hashrates[pre_b.miner_id], hashrates[cur_b.miner_id]], [pre_b.height, cur_b.height], 'k-',cols[t_block.miner_id%4])
			# #pylab.plot([pre_b.miner_id, cur_b.miner_id], [pre_b.height, cur_b.height], 'k-')


# #print('Number of orphan blocks: %d' %orphans)
# #pylab.ylabel('block height')
# ##pylab.xlabel('hashrate')
# #pylab.xlabel('Miner_id')
# #pylab.ylim([0, 100])
# #pylab.draw()


# #print('Orphaned blocks: %d (%0.3f)' % (orphans, orphans/mine.blocks[mine.chain_head].height))
# print('Average block height time: %0.3f min' % (mine.blocks[mine.chain_head].time/(60*mine.blocks[mine.chain_head].height)))

# #pylab.show()

l = np.zeros(n)
for i in range(n):
	#print(len(miners[i].block_time))
	#print(miners[i].block_time)
	l[i] = len(miners[i].block_time)
	

L = int(min(l))
prop_time = np.zeros((len(miners[0].block_time), n))
sorted_time = np.zeros((len(miners[0].block_time), n))
k = 0
for x in miners[0].block_time.keys():
	k = k+1
	for i in range(n):
		#print(x, miners[i].block_time[x])
		prop_time[x-1][i] = miners[i].block_time[x]
	# print(k)
	
for i in range(len(prop_time)):
	 #print(prop_time[i])
	 sorted_time[i] = sorted(prop_time[i])
	 sorted_time[i] = sorted_time[i] - sorted_time[i][0] 
		
print(prop_time[0])
print(sorted_time[0])

t = []
t.append(0.0)
k = 0
x = []
x.append(1)
for i in range(1,len(sorted_time[0])):
	#if(sorted_time[0][i] > t[k]):
	t.append(sorted_time[0][i])
	x.append(i)
	k += 1
		
		
	
	

pylab.figure()
pylab.plot(x,t)
pylab.xlabel('Number of nodes')
pylab.ylabel('Time since first observation of block')
pylab.grid()
pylab.show()
		




