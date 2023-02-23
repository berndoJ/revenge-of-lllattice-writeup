#!/usr/bin/python3

# Revenge of LLLattice Challenge
# pbctf 2023

# Copyright (c) 2023 Team CyberSecurityAustria
# Authors: Johannes Berndorfer (@berndoJ) & Jonas Konrad (@austriangam3r)

# This file simulates the FPGA design with random values for v0 and v1 and
# extracts the v0/v1 values after one encryption round. As a sanity check,
# also the original plaintext v0/v1 are extracted.
# As we need multiple samples for the bruteforce, this script generates a file
# with a specified number of samples.

from pwn import *
import struct
import io
from vcd.reader import TokenKind, tokenize
import random
from datetime import datetime
import json
import re

# The number of samples to generate
SAMPLE_COUNT = 16

# Signal mappings. Bit 0 is LSB.
SIGNALS_V0_STAGE0 = {
    0:  "_R4C27_PLC2_inst.sliceB_inst.ff_1.Q",
    1:  "_R20C29_PLC2_inst.sliceC_inst.ff_1.Q",
    2:  "_R4C28_PLC2_inst.sliceC_inst.ff_0.Q",
    3:  "_R3C29_PLC2_inst.sliceC_inst.ff_0.Q",
    4:  "_R4C29_PLC2_inst.sliceB_inst.ff_0.Q",
    5:  "_R3C28_PLC2_inst.sliceC_inst.ff_0.Q",
    6:  "_R3C30_PLC2_inst.sliceB_inst.ff_1.Q",
    7:  "_R3C32_PLC2_inst.sliceD_inst.ff_1.Q",

    8:  "_R4C30_PLC2_inst.sliceC_inst.ff_1.Q",
    9:  "_R4C32_PLC2_inst.sliceC_inst.ff_0.Q",
    10: "_R4C31_PLC2_inst.sliceC_inst.ff_0.Q",
    11: "_R6C30_PLC2_inst.sliceA_inst.ff_1.Q",
    12: "_R6C31_PLC2_inst.sliceD_inst.ff_0.Q",
    13: "_R7C30_PLC2_inst.sliceB_inst.ff_1.Q",
    14: "_R7C32_PLC2_inst.sliceA_inst.ff_0.Q",
    15: "_R5C32_PLC2_inst.sliceC_inst.ff_0.Q",

    16: "_R3C31_PLC2_inst.sliceA_inst.ff_1.Q",
    17: "_R7C31_PLC2_inst.sliceB_inst.ff_1.Q",
    18: "_R4C33_PLC2_inst.sliceD_inst.ff_1.Q",
    19: "_R8C32_PLC2_inst.sliceD_inst.ff_0.Q",
    20: "_R7C33_PLC2_inst.sliceD_inst.ff_0.Q",
    21: "_R6C32_PLC2_inst.sliceC_inst.ff_1.Q",
    22: "_R4C34_PLC2_inst.sliceB_inst.ff_1.Q",
    23: "_R3C33_PLC2_inst.sliceA_inst.ff_0.Q",

    24: "_R27C33_PLC2_inst.sliceB_inst.ff_0.Q",
    25: "_R23C33_PLC2_inst.sliceA_inst.ff_0.Q",
    26: "_R26C34_PLC2_inst.sliceC_inst.ff_0.Q",
    27: "_R22C35_PLC2_inst.sliceA_inst.ff_0.Q",
    28: "_R24C35_PLC2_inst.sliceA_inst.ff_0.Q",
    29: "_R23C34_PLC2_inst.sliceA_inst.ff_0.Q",
    30: "_R29C34_PLC2_inst.sliceC_inst.ff_1.Q",
    31: "_R23C35_PLC2_inst.sliceA_inst.ff_0.Q"
}

SIGNALS_V0_STAGE1 = {
    0:  "_R10C30_PLC2_inst.sliceB_inst.ff_0.Q",
    1:  "_R11C29_PLC2_inst.sliceD_inst.ff_0.Q",
    2:  "_R12C28_PLC2_inst.sliceD_inst.ff_0.Q",
    3:  "_R17C29_PLC2_inst.sliceC_inst.ff_0.Q",
    4:  "_R11C28_PLC2_inst.sliceC_inst.ff_1.Q",
    5:  "_R17C28_PLC2_inst.sliceB_inst.ff_0.Q",
    6:  "_R10C31_PLC2_inst.sliceA_inst.ff_0.Q",
    7:  "_R11C31_PLC2_inst.sliceC_inst.ff_1.Q",

    8:  "_R12C32_PLC2_inst.sliceA_inst.ff_1.Q",
    9:  "_R10C28_PLC2_inst.sliceB_inst.ff_0.Q",
    10: "_R9C31_PLC2_inst.sliceC_inst.ff_1.Q",
    11: "_R10C29_PLC2_inst.sliceA_inst.ff_1.Q",
    12: "_R11C32_PLC2_inst.sliceD_inst.ff_1.Q",
    13: "_R15C32_PLC2_inst.sliceC_inst.ff_0.Q",
    14: "_R12C33_PLC2_inst.sliceA_inst.ff_0.Q",
    15: "_R21C32_PLC2_inst.sliceC_inst.ff_0.Q",

    16: "_R15C33_PLC2_inst.sliceD_inst.ff_1.Q",
    17: "_R11C33_PLC2_inst.sliceD_inst.ff_1.Q",
    18: "_R16C33_PLC2_inst.sliceC_inst.ff_0.Q",
    19: "_R21C33_PLC2_inst.sliceB_inst.ff_0.Q",
    20: "_R19C33_PLC2_inst.sliceD_inst.ff_1.Q",
    21: "_R10C32_PLC2_inst.sliceD_inst.ff_1.Q",
    22: "_R10C33_PLC2_inst.sliceA_inst.ff_0.Q",
    23: "_R9C33_PLC2_inst.sliceD_inst.ff_0.Q",

    24: "_R12C34_PLC2_inst.sliceA_inst.ff_1.Q",
    25: "_R10C35_PLC2_inst.sliceA_inst.ff_1.Q",
    26: "_R11C35_PLC2_inst.sliceD_inst.ff_0.Q",
    27: "_R12C35_PLC2_inst.sliceB_inst.ff_0.Q",
    28: "_R11C34_PLC2_inst.sliceA_inst.ff_1.Q",
    29: "_R21C34_PLC2_inst.sliceC_inst.ff_0.Q",
    30: "_R9C34_PLC2_inst.sliceA_inst.ff_1.Q",
    31: "_R10C34_PLC2_inst.sliceA_inst.ff_1.Q"
}

SIGNALS_V1_STAGE0 = {
    0:  "_R2C31_PLC2_inst.sliceB_inst.ff_1.Q",
    1:  "_R2C28_PLC2_inst.sliceD_inst.ff_1.Q",
    2:  "_R6C28_PLC2_inst.sliceA_inst.ff_0.Q",
    3:  "_R5C33_PLC2_inst.sliceA_inst.ff_0.Q",
    4:  "_R6C29_PLC2_inst.sliceD_inst.ff_0.Q",
    5:  "_R6C34_PLC2_inst.sliceC_inst.ff_1.Q",
    6:  "_R7C34_PLC2_inst.sliceC_inst.ff_1.Q",
    7:  "_R5C34_PLC2_inst.sliceB_inst.ff_0.Q",

    8:  "_R6C33_PLC2_inst.sliceB_inst.ff_1.Q",
    9:  "_R2C32_PLC2_inst.sliceC_inst.ff_0.Q",
    10: "_R2C29_PLC2_inst.sliceD_inst.ff_0.Q",
    11: "_R2C34_PLC2_inst.sliceD_inst.ff_0.Q",
    12: "_R5C35_PLC2_inst.sliceB_inst.ff_1.Q",
    13: "_R2C30_PLC2_inst.sliceD_inst.ff_1.Q",
    14: "_R17C34_PLC2_inst.sliceA_inst.ff_1.Q",
    15: "_R3C35_PLC2_inst.sliceB_inst.ff_1.Q",

    16: "_R2C33_PLC2_inst.sliceA_inst.ff_0.Q",
    17: "_R4C36_PLC2_inst.sliceC_inst.ff_1.Q",
    18: "_R8C30_PLC2_inst.sliceD_inst.ff_0.Q",
    19: "_R7C29_PLC2_inst.sliceC_inst.ff_0.Q",
    20: "_R8C35_PLC2_inst.sliceA_inst.ff_1.Q",
    21: "_R7C35_PLC2_inst.sliceD_inst.ff_1.Q",
    22: "_R8C34_PLC2_inst.sliceD_inst.ff_0.Q",
    23: "_R5C36_PLC2_inst.sliceC_inst.ff_0.Q",

    24: "_R4C37_PLC2_inst.sliceC_inst.ff_1.Q",
    25: "_R3C37_PLC2_inst.sliceC_inst.ff_1.Q",
    26: "_R6C36_PLC2_inst.sliceA_inst.ff_0.Q",
    27: "_R6C35_PLC2_inst.sliceD_inst.ff_0.Q",
    28: "_R4C35_PLC2_inst.sliceD_inst.ff_0.Q",
    29: "_R9C36_PLC2_inst.sliceB_inst.ff_0.Q",
    30: "_R3C36_PLC2_inst.sliceB_inst.ff_0.Q", 
    31: "_R10C36_PLC2_inst.sliceA_inst.ff_1.Q"
}

SIGNALS_V1_STAGE1 = {
    0:  "_R5C27_PLC2_inst.sliceB_inst.ff_0.Q",
    1:  "_R12C36_PLC2_inst.sliceA_inst.ff_1.Q",
    2:  "_R9C29_PLC2_inst.sliceB_inst.ff_1.Q",
    3:  "_R8C29_PLC2_inst.sliceB_inst.ff_0.Q",
    4:  "_R9C28_PLC2_inst.sliceD_inst.ff_1.Q",
    5:  "_R14C28_PLC2_inst.sliceD_inst.ff_0.Q",
    6:  "_R5C28_PLC2_inst.sliceA_inst.ff_0.Q",
    7:  "_R9C30_PLC2_inst.sliceD_inst.ff_1.Q",

    8:  "_R14C34_PLC2_inst.sliceA_inst.ff_1.Q",
    9:  "_R15C30_PLC2_inst.sliceA_inst.ff_1.Q",
    10: "_R11C30_PLC2_inst.sliceB_inst.ff_0.Q",
    11: "_R12C27_PLC2_inst.sliceD_inst.ff_0.Q",
    12: "_R12C31_PLC2_inst.sliceC_inst.ff_0.Q",
    13: "_R12C30_PLC2_inst.sliceD_inst.ff_1.Q",
    14: "_R5C29_PLC2_inst.sliceA_inst.ff_0.Q",
    15: "_R8C31_PLC2_inst.sliceA_inst.ff_1.Q",

    16: "_R9C32_PLC2_inst.sliceC_inst.ff_0.Q",
    17: "_R12C29_PLC2_inst.sliceB_inst.ff_1.Q",
    18: "_R14C35_PLC2_inst.sliceA_inst.ff_1.Q",
    19: "_R15C34_PLC2_inst.sliceD_inst.ff_0.Q",
    20: "_R15C31_PLC2_inst.sliceD_inst.ff_1.Q",
    21: "_R19C32_PLC2_inst.sliceD_inst.ff_0.Q",
    22: "_R5C30_PLC2_inst.sliceA_inst.ff_0.Q",
    23: "_R17C33_PLC2_inst.sliceD_inst.ff_1.Q",

    24: "_R8C33_PLC2_inst.sliceB_inst.ff_0.Q",
    25: "_R14C27_PLC2_inst.sliceB_inst.ff_1.Q",
    26: "_R19C34_PLC2_inst.sliceB_inst.ff_0.Q",
    27: "_R19C35_PLC2_inst.sliceD_inst.ff_0.Q",
    28: "_R9C35_PLC2_inst.sliceB_inst.ff_0.Q",
    29: "_R16C32_PLC2_inst.sliceC_inst.ff_1.Q",
    30: "_R5C31_PLC2_inst.sliceA_inst.ff_0.Q",
    31: "_R20C35_PLC2_inst.sliceD_inst.ff_1.Q"
}  

def oracle(byte_list : list):
    if len(byte_list) != 8:
        return None

    payload = b""
    for byte in byte_list:
        payload += b"%02x " % byte
    
    p = process("/usr/local/bin/vvp ../verilog/chall_tb", shell=True)
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

    p.close()
    
    return resp

def main():
    random.seed(datetime.now().timestamp())

    samples = []

    # Run oracle once and extract stage 0 and stage 1 signals from vcd dump.
    for pair_idx in range(SAMPLE_COUNT):
        v0 = random.randint(0, 2**32-1) & 0xffffffff
        v1 = random.randint(0, 2**32-1) & 0xffffffff
        payload_list = list(bytearray(struct.pack("<I", v1)))
        payload_list.extend(list(bytearray(struct.pack("<I", v0))))

        _ = oracle(payload_list)

        # VCD file contains our data from the simulation by the oracle.
        with open("./dump.vcd", "rb") as vcd_f:
            vcd = vcd_f.read()

        # Replace signal '\' tokens with '_', otherwise vcdpy will hang itself...
        vcd = vcd.decode("ascii")
        vcd = re.sub(r"(\\)(?=[^ ]+ \$end+)+", "_", vcd)
        vcd = vcd.encode("ascii")

        # Extract tokens from dumped VCD file.
        tokens = tokenize(io.BytesIO(vcd))

        lookup = {}

        times = {}
        current_time = 0
        i=0
        for token in  tokens:
            if token.kind == TokenKind.VAR:
                lookup[token.data.id_code] = token.data.reference
            elif token.kind == TokenKind.CHANGE_SCALAR:
                if current_time in times:
                    if not lookup[token.data.id_code].endswith(".Q"):
                        continue
                    times[current_time][lookup[token.data.id_code]]=token.data.value
                else:
                    if not lookup[token.data.id_code].endswith(".Q"):
                        continue
                    times[current_time]={lookup[token.data.id_code]: token.data.value }
            elif token.kind == TokenKind.CHANGE_TIME:
                current_time = token.data
            i+=1

        # Get the final value of all the signals that we are interested in.
        # Warning: The following code is pretty ugly, but it works.
        sig_final_values = {
            "v0_stage0": {},
            "v0_stage1": {},
            "v1_stage0": {},
            "v1_stage1": {}
        }

        # v0 stage 0
        for sig_idx in SIGNALS_V0_STAGE0:
            sig = SIGNALS_V0_STAGE0[sig_idx]
            sig_final_value = 0
            for time in times:
                if time < 1000 or time >= 7410060:
                    continue
                if sig in times[time]:
                    sig_final_value = int(times[time][sig])
            sig_final_values["v0_stage0"][sig_idx] = sig_final_value

        # v0 stage 1
        for sig_idx in SIGNALS_V0_STAGE1:
            sig = SIGNALS_V0_STAGE1[sig_idx]
            sig_final_value = 0
            for time in times:
                if time < 1000 or time > 7410060:
                    continue
                if sig in times[time]:
                    sig_final_value = int(times[time][sig])
            sig_final_values["v0_stage1"][sig_idx] = sig_final_value

        # v1 stage 0
        for sig_idx in SIGNALS_V1_STAGE0:
            sig = SIGNALS_V1_STAGE0[sig_idx]
            sig_final_value = 0
            for time in times:
                if time < 1000 or time >= 7410060:
                    continue
                if sig in times[time]:
                    sig_final_value = int(times[time][sig])
            sig_final_values["v1_stage0"][sig_idx] = sig_final_value

        # v1 stage 1
        for sig_idx in SIGNALS_V1_STAGE1:
            sig = SIGNALS_V1_STAGE1[sig_idx]
            sig_final_value = 0
            for time in times:
                if time < 1000 or time > 7410060:
                    continue
                if sig in times[time]:
                    sig_final_value = int(times[time][sig])
            sig_final_values["v1_stage1"][sig_idx] = sig_final_value

        # Generate 32bit representatives of v0 and v1 at both stages.
        sample = {
            0: {"v0": 0, "v1": 0},
            1: {"v0": 0, "v1": 0}
        }

        for i in range(32):
            sample[0]["v0"] |= (sig_final_values["v0_stage0"][i] << i)
            sample[0]["v1"] |= (sig_final_values["v1_stage0"][i] << i)
            sample[1]["v0"] |= (sig_final_values["v0_stage1"][i] << i)
            sample[1]["v1"] |= (sig_final_values["v1_stage1"][i] << i)
        
        # Swap v0/v1 in both stages, because it happens to be the other way ...
        v0, v1 = v1, v0
        sample[0]["v0"], sample[0]["v1"] = sample[0]["v1"], sample[0]["v0"]
        sample[1]["v0"], sample[1]["v1"] = sample[1]["v1"], sample[1]["v0"]

        # Stage 0 sanity check.
        if sample[0]["v0"] != v0 or sample[0]["v1"] != v1:
            print("Error: Input v0/v1 and extracted v0/v1 do not match:")
            print("v0_extracted=0x%08x v0_in=0x%08x" % (sample[0]["v0"], v0))
            print("v1_extracted=0x%08x v1_in=0x%08x" % (sample[0]["v1"], v1))
            print("v0 XOR map: 0b{0:032b}".format(sample[0]["v0"] ^ v0))
            print("v1 XOR map: 0b{0:032b}".format(sample[0]["v1"] ^ v1))
            print("Skipping.")
            continue

        samples.append(sample)

    # Export to sample file.
    # Format: v0-plain v1-plain v0-cipher v1-cipher
    with open("tea_round_samples.log", "w") as out_file:
        for sample in samples:
            line = "%i %i %i %i\n" % (sample[0]["v0"], sample[0]["v1"], sample[1]["v0"], sample[1]["v1"])
            out_file.write(line)

if __name__ == "__main__":
    main()