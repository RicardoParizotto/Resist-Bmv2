# Implementing Switch Fault Tolerance

## Introduction

The objective of this program is to make switches fault tolerant
with an asynchronous replication technique. We are going to use a simple topology of
two switches (a master and a replica) to exemplify the functionality of the system.

#1 How to run:

Download the VM with bmv2

use the script run.py to run a experiment by passing the number of hosts as parameter 


The current experiments consider the following topology:

![Screenshot](topo/topo.png)

This implementation uses a single coordinator at 

> scoordinatorAdress = "10.0.3.3"

In case of failures, this coordinator is going to be used for aggregating shim-layer informations from all the hosts. 

We consider N hosts with two interfaces. By default interface h0 forwards packets to the replica, while hN is used to forward packets to the replica. 