#!/usr/bin/python3
import re
import os
import operator
import json
import argparse
import time
from collections import defaultdict
from collections import Counter
from collections import deque
from collections import namedtuple
import math
import sys
import pandas as pd


# INPUT FILES
# Flow trace to classify
flow_file=sys.argv[1]
# Bags of domains in JSON format
rules_file=sys.argv[2]


# OUTPUT FILE
# Classified flows
output_file_name = sys.argv[3]

# DEFAULT PARAMETERS
# Timeout to consider association [s]
timeout=10
# Minimum frequency of domain inside a bag
ratio_th = 0.0625

# Define Window named tuple
Window = namedtuple( "wnd", ["start", "end"])



print("Using input flow trace file:", flow_file)

print("Using input BoDs:", rules_file)
        

def main():  

    rules_json = import_dict(rules_file)

    rules = filter_rules(rules_json, ratio_th)
            
    # Parse file
    parse_file(flow_file, output_file_name, rules)    


def parse_file(file_name, output_file_name, rules):
    
    # INITIALIZE DATA STRUCTURES
    # Data structures
    last_cores = defaultdict(dict)
    last_flows = defaultdict(deque)

    # Open file
    fp=open(file_name,"r")
    fo=open(output_file_name,"w")
    fo.write("time,server,domain,service,output\n")
    non_core_flows = 0

    # Creating precedences for each flow
    old_instant=time.time()
    rows = fp.read().splitlines()


    for row in rows:  

        try:
            (c_ip, curr_time, name) = parse_row(row)
        except:
            continue

        
        # Delete old core domains - "Garbage collection"
        for core in list(last_cores[c_ip].keys()):
            if last_cores[c_ip][core].end < curr_time:
                del last_cores[c_ip][core] 

        # Delete list of last domains
        for old_time, old_domain in list(last_flows[c_ip]):
            if curr_time - old_time > timeout*5:
                last_flows[c_ip].popleft()



        # Check if it is a core                
        if name in rules and is_valid_trigger(c_ip, last_cores[c_ip], name, rules):

            last_cores[c_ip][name] = Window (curr_time, curr_time + timeout)

            # Write log
            prevision = name
            fo.write(row + "," + prevision + "\n")
          
            # Add history flows
            tup = (curr_time, name)
            last_flows[c_ip].append(tup)
        
        # It is not a trigger     
        else:

            # Check last core domains
            if c_ip in last_cores:
                last_cores_sorted = sorted(last_cores[c_ip].items(), key = lambda t: t[1].start, reverse=True)
                max_score = 0
                for core, visit_time  in last_cores_sorted:
                    if name in rules[core]:
                        max_trigger=core
                        max_score=1
                        last_cores[c_ip][core]=Window(last_cores[c_ip][core].start, \
                                               max ( last_cores[c_ip][core].end, curr_time+timeout) ) 
                        break
            
            # Write log
            if max_score == 0:
                prevision = "UNKNOWN"
            else:
                prevision = max_trigger

          
            fo.write(row + "," + prevision + "\n")

            # Add history flows
            tup = (curr_time, name)
            last_flows[c_ip].append(tup)


    
def is_valid_trigger (c_ip, last_cores_dict, name, rules):


    # Return True if there isn't any open window
    last_cores_sorted = sorted (last_cores_dict.items(), key = lambda t: t[1].start, reverse=True )
    if last_cores_sorted == []:
        return True
    
    # Find the last window. Search for an open window whose bag contains the current domain
    found_core_in_bag = False
    for last_core, last_window_times in last_cores_sorted:
        if name in rules[last_core]:
            found_core_in_bag = True
            break
    # If this domain is in the bag of an active core, return False
    if found_core_in_bag == False:
        return True
    else:
        return False



def dump_to_file(file_name, dictionary):
    
    f=open(file_name, "w")
    f.write(json.dumps(dictionary))

def distance_window_bag ( window, bag ):

    if len(window)==0:
        return 0
    score = 0
    for domain in window:
        if domain in bag:
            tmp_score = window[domain]*bag[domain]
        else:
            tmp_score = 0
        score+=tmp_score
    score = score /len(window)
    return score

def import_dict(file):
    json_data=open(file,"r").read()
    return json.loads(json_data)

def filter_rules(rules_json, ratio_th):
    rules=rules_json["bags"]
    all_domains=Counter()
    rules_new = defaultdict(dict)
    for core in rules:
        if core in rules_json["occurrencies"]:
            for found in rules[core]:
                if rules[core][found]>= ratio_th:
                    rules_new[core][found] = rules[core][found]
                    all_domains[found] += 1
                
    length = len (rules_new)            
    for core in rules_new:
        for found in rules_new[core]:
            rules_new[core][found] =  rules_new[core][found] * math.log10(length/all_domains[found])          

                
    return rules_new

def parse_row(line):
    fields=line.split(",")

    name=fields[2]
    c_ip="0.0.0.0"
    time=float(fields[0])

    return (c_ip, time, name)



main()



