#!/usr/bin/env python3
# -.- coding: utf-8 -.-

try:
    import os
    import sys
    import time
    import json
    import pyshark
    import sqlite3
    import datetime
    import argparse
    import threading
    import traceback
    import urllib.request as urllib2
except KeyboardInterrupt:
    print("\n[I] Stopping...")
    raise SystemExit
except:
    print("[!] Failed to import the dependencies... " +\
            "Please make sure to install all of the requirements " +\
            "and try again.")
    raise SystemExit

parser = argparse.ArgumentParser(
    usage="probeSniffer.py [monitor-mode-interface] [options]")
parser.add_argument(
    "interface", help='interface (in monitor mode) for capturing the packets')
parser.add_argument("-d", action='store_true',
                    help='do not show duplicate requests')
parser.add_argument("-b", action='store_true',
                    help='do not show \'broadcast\' requests (without ssid)')
parser.add_argument("-a", action='store_true',
                    help='save duplicate requests to SQL')
parser.add_argument("--filter", type=str,
                    help='only show requests from the specified mac address')
parser.add_argument('--norssi', action='store_true',
                    help="include rssi in output")
parser.add_argument("--nosql", action='store_true',
                    help='disable SQL logging completely')
parser.add_argument("--addnicks", action='store_true',
                    help='add nicknames to mac addresses')
parser.add_argument("--flushnicks", action='store_true',
                    help='flush nickname database')
parser.add_argument('--noresolve', action='store_true',
                    help="skip resolving mac address")
parser.add_argument("--debug", action='store_true', help='turn debug mode on')
parser.add_argument("--output", type=str, help='output file path')

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)
args = parser.parse_args()
showDuplicates = not args.d
showBroadcasts = not args.b
noSQL = args.nosql
addNicks = args.addnicks
flushNicks = args.flushnicks
debugMode = args.debug
saveDuplicates = args.a
filterMode = args.filter != None
norssi = args.norssi
noresolve = args.noresolve
output_file = args.output
if args.filter != None:
    filterMac = args.filter

monitor_iface = args.interface
alreadyStopping = False


def restart_line():
    sys.stdout.write('\r')
    sys.stdout.flush()


def statusWidget(devices):
    if not filterMode:
        sys.stdout.write("Devices found: [" + str(devices) + "]")
    else:
        sys.stdout.write("Devices found: [FILTER MODE]")
    restart_line()
    sys.stdout.flush()


header = """
 ____  ____   ___  ____    ___ _________  ____ _____ _____  ___ ____
|    \|    \ /   \|    \  /  _/ ___|    \|    |     |     |/  _|    \\
|  o  |  D  |     |  o  )/  [(   \_|  _  ||  ||   __|   __/  [_|  D  )
|   _/|    /|  O  |     |    _\__  |  |  ||  ||  |_ |  |_|    _|    /
|  |  |    \|     |  O  |   [_/  \ |  |  ||  ||   _
|  |  |  .  |     |     |     \    |  |  ||  ||  |  |  | |   _]  |
|__|  |__|\_|_____|_____|\____|\___|__|__|____|__|  |__| |__| |__|
"""

print(header)

# Create a SQLite database to store duplicate requests
if not noSQL:
    conn = sqlite3.connect('probes.db')
    c = conn.cursor()
    try:
        c.execute(
            '''CREATE TABLE IF NOT EXISTS duplicates
                 (mac TEXT, ssid TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        conn.commit()
    except sqlite3.OperationalError as e:
        print("[!] Error creating SQLite database:", e)
        noSQL = True

# Check if output file path is provided
if output_file:
    try:
        output_file = open(output_file, 'w')
    except IOError:
        print("[!] Failed to open output file:", output_file)
        output_file = None

# Load the nickname database
nicknames = {}
try:
    with open('nicknames.json', 'r') as file:
        nicknames = json.load(file)
except (IOError, ValueError):
    nicknames = {}

# Function to save duplicate requests to the SQLite database
def save_duplicate(mac, ssid):
    if noSQL:
        return
    try:
        c.execute(
            '''INSERT INTO duplicates (mac, ssid) VALUES (?, ?)''', (mac, ssid))
        conn.commit()
    except sqlite3.OperationalError as e:
        print("[!] Error saving duplicate to SQLite database:", e)

# Function to process and analyze captured probe requests
def process_probe_request(pkt):
    global alreadyStopping

    if pkt and pkt.haslayer("Dot11ProbeReq"):
        try:
            mac_address = pkt.addr2
            ssid = pkt.info.decode("utf-8")
            rssi = pkt.dBm_AntSignal if norssi else None

            # Filter mode: Only show requests from the specified MAC address
            if filterMode and mac_address.lower() != filterMac.lower():
                return

            # Skip duplicate requests if showDuplicates is disabled
            if not showDuplicates and (mac_address, ssid) in devices:
                return

            # Skip broadcast requests if showBroadcasts is disabled
            if not showBroadcasts and ssid == "":
                return

            # Display the probe request information
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            output = f"[{timestamp}] {mac_address} - {ssid}"
            if rssi:
                output += f" (RSSI: {rssi})"
            print(output)

            # Write to output file if provided
            if output_file:
                output_file.write(output + "\n")
                output_file.flush()

            # Save duplicate requests to SQLite database if saveDuplicates is enabled
            if saveDuplicates:
                threading.Thread(target=save_duplicate, args=(mac_address, ssid)).start()

            # Add nickname to the MAC address
            if addNicks and mac_address not in nicknames:
                nickname = input(f"Enter a nickname for {mac_address}: ")
                nicknames[mac_address] = nickname
                with open('nicknames.json', 'w') as file:
                    json.dump(nicknames, file)

            # Add the probe request to the devices set
            devices.add((mac_address, ssid))

        except Exception as e:
            if debugMode:
                traceback.print_exc()

    # Stop capturing if alreadyStopping flag is set
    if alreadyStopping:
        raise KeyboardInterrupt

# Create a packet sniffer and apply the process_probe_request function to each captured packet
try:
    sniff(iface=interface, prn=process_probe_request, stop_filter=lambda x: alreadyStopping, store=0)
except KeyboardInterrupt:
    print("[+] Stopping...")
