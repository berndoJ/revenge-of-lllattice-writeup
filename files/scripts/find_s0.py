#!/usr/bin/python3

# Revenge of LLLattice Challenge
# pbctf 2023

# Copyright (c) 2023 Team CyberSecurityAustria
# Authors: Jonas Konrad (@jalaka)

# This script performs a statistical analysis (multithreaded) to dump the FFs
# of stage 0 (plaintext).

import io
from vcd.reader import TokenKind, tokenize
import os
from pwn import * 
from multiprocessing import Pool
import re
context.log_level = 'error'

#Interact with the fpga simulation
def oracle(byte_list : list, id):
    if len(byte_list) != 8:
        return None

    payload = b""
    for byte in byte_list:
        payload += b"%02x " % byte
    try:
        os.mkdir(f"dirs/{id}")
    except OSError as error:
        pass
    os.chdir(f'dirs/{id}')
    p = process(f"/usr/local/bin/vvp ../verilog/chall_tb", shell=True)
    p.sendline(payload)

    p.recvuntil(b"=== FPGA DATA BEGIN ===\n")

    # read 8 response bytes.
    resp = []
    for i in range(8):
        resp_str = p.recvuntil(b"\n")
        try:
            resp.append(int(resp_str, 16))
        except Exception:
            return None
    
    return resp
#We use multiprocessing to run multiple simulations in parallel
def procWrapper(bitmask,direction,timestep,sample_count):
    with Pool(sample_count) as pool:
        samples = pool.starmap(proc, [(bitmask,direction,i) for i in range(0,sample_count)])

    flops = {}
    for sample in samples:
        for x in sample[timestep]:
            if x not in flops:
                flops[x] = 0
            if(sample[timestep][x]=="1"):
                flops[x]+=1
    flops = dict(sorted(flops.items(), key=lambda item: item[1], reverse=True))
    return flops

def proc(bitmask,direction,id):
    #Generate a random string and flip the bit at the given index, which is the bit we are trying to find the name of
    random_string = os.urandom(8)
    int_val = int.from_bytes(random_string, "big")
    if direction:
        int_val&=~bitmask
    else:
        int_val|=bitmask
        
    rand_string = int_val.to_bytes(8, "big")
    oracle(list(rand_string),id)
    with open(f"dump.vcd","rb") as f:
        vcd = f.read()

    # Replace signal '\' tokens with '_', otherwise vcdpy will hang itself...
    vcd = vcd.decode("ascii")
    vcd = re.sub(r"(\\)(?=[^ ]+ \$end+)+", "_", vcd)
    vcd = vcd.encode("ascii")

    tokens = tokenize(io.BytesIO(vcd))

    lookup = {}

    time_steps = {}
    current_time = 0
    i=0
    #Parse the vcd file and save the last value of each flop at each timestep
    for token in  tokens:
        if token.kind == TokenKind.VAR:
            lookup[token.data.id_code] = token.data.reference
        elif token.kind == TokenKind.CHANGE_SCALAR:
            #Only find flops and not wires or IO
            if not lookup[token.data.id_code].endswith("Q"):
                continue
            if current_time in time_steps:
                time_steps[current_time][lookup[token.data.id_code]]=token.data.value
            else:
                time_steps[current_time]={lookup[token.data.id_code]: token.data.value }
        elif token.kind == TokenKind.CHANGE_TIME:
            current_time = token.data
        else:
            pass
        i+=1
    state = {}
    latched_values = {}
    for tick in time_steps.keys():
        for flop, value in time_steps[tick].items():
            #update latest value of flop
            latched_values[flop] = value
        state[tick] = latched_values

    return state

#We check the samples for stage0 at timestep 7410060, which is the first time after the uart that a lot of flops are set
#15 samples are enough to get a good idea of the flops used for each bit
def getNameForBit(index,timestep=7410060,sample_count=15):
    first = procWrapper(1<<index,False,timestep,sample_count)
    second = procWrapper(1<<index,True,timestep,sample_count)

    first =[x[0] for x in list(filter(lambda x: x[1]==sample_count, first.items()))]
    second =[x[0] for x in list(filter(lambda x: x[1]==sample_count, second.items()))]
    
    #Check samples for which the bit is set and not set, and calculate the difference
    candidates = []
    for element in first:
        if element not in second:
            candidates.append(element)
    #if more than one flop is found try again with more samples
    if len(candidates)!=1:
        candidates = getNameForBit(index,timestep,sample_count+5)
    return candidates

#Print the candidates names of the flops for each bit
for i in range(0,64):
    print(i,getNameForBit(i))
