#!/usr/bin/python3
import operator
import json
import re 
from collections import defaultdict
import sys
import statistics

# PARAMETERS
# Observation Window [s]
t_ow=10
# The gap [s]
t_idle = 5 


# INPUT
# Services to monitor
sites_file=sys.argv[1]
# Trace to process
flow_file=sys.argv[2]
# OUTUPUT
# Bags of Domains, in JSON format
rules_file=sys.argv[3]


# Global vars
rules={}
occurrencies={}
durations={}
sites=[]

def main():
    
    # Import global variables
    global rules
    global rules_cluster
    global sites
    global occurrencies

        
    # Read target sites
    print("Using services file: ", sites_file)
    sites=set(open(sites_file, "r").read().splitlines())    
    
    # Parse file
    print("Using input trace: ", flow_file)
    parse_file(flow_file)    
    
    
    # Filter rules
    rules = filter_rules(rules)
    
    # Dump on file
    rules_to_dump = {"bags":rules, "occurrencies": occurrencies}
    dump_to_file(rules_file, rules_to_dump)


def parse_file(file_name):
    
    # Import global variables
    global rules
    global sites
    global occurrencies
    global ip_addresses
    global duration_samples
    global durations
    
    # Open file
    fp=open(file_name,"r")
    
    # Creating dictionaries
    precedences=defaultdict(lambda : defaultdict( lambda : [] ))
    current_windows=defaultdict(lambda : ("-", 0) )
    times=defaultdict(lambda: -2**32 )
    
    start_time = -1
    
    # Creating precedences for each flow
    for row in fp:    

        try:
            fields=row.split(",")
            
            # Extract fields   
            c_ip="0.0.0.0"
            s_ip=fields[1]
            time=float(fields[0])
            name = fields[2]
            
            
            # Update last activity time for that client always (even where there is no name)
            old_time=times[c_ip]
            times[c_ip]=time

            # If it is a core domain
            if name in sites and time-old_time > t_idle and time-current_windows[c_ip][1] > t_ow :              
                
                # Create dictionary entry for this client
                if not c_ip in precedences:
                    precedences[c_ip]={}
                # Create names entry for that client    
                if not name in precedences[c_ip]:
                    precedences[c_ip][name]=[]
                    
                # Update occurrencies
                if not name in occurrencies:
                    occurrencies[name]=1
                else:
                    occurrencies[name] += 1
                
                current_windows[c_ip]=(name,time)
                
                
            # Asssociate a flow to the dictionary
            elif time - current_windows[c_ip][1] < t_ow and current_windows[c_ip][0] != "-":
                precedences[c_ip][ current_windows[c_ip][0] ].append(name) 

        except:
            pass

    print("File read. Consolidating results...")
    # Build the rules
    for c_ip in precedences:
        # For each server
        for server_name in precedences[c_ip]:
            # Create rule entry if it doesn't exists
            if not server_name in rules:
                rules[server_name]={}
            #For each found name
            for found_name in precedences[c_ip][server_name]:
                #Create entry if not exists
                if not  found_name in rules[server_name]:
                    rules[server_name][found_name]=1
                #Update it if exists
                else:
                    rules[server_name][found_name] += 1

# Transform the absolute occurencies in percentages
def filter_rules(rules):
    
    # Import global variables
    global sites
    global occurrencies
    new_rules={}
    
    for server_name in rules:
        
        # Create entry in new dictonary
        new_rules[server_name]={}
        
        # Calculate relative frequency
        for found_name in rules[server_name]:
            new_rules[server_name][found_name]=rules[server_name][found_name]/occurrencies[server_name]
     
    return new_rules           


def dump_to_file(file_name, dictionary):
    
    f=open(file_name, "w")
    f.write(json.dumps(dictionary))


main()



