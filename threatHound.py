#!/usr/bin/env python3

import curses
import os
import readline
import sniffer
import sys

NORMAL = '\033[1;m'
RED = '\033[1;31m'
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'


def main():
    # Check for root privilege
    is_root()
    # Clear the screen
    os.system('clear')
    # Pass banner
    text = banner('''
      ________                    __  __  __                      __
     /_  __/ /_  ________  ____ _/ /_/ / / /___  __  ______  ____/ /
      / / / __ \/ ___/ _ \/ __ `/ __/ /_/ / __ \/ / / / __ \/ __  /
     / / / / / / /  /  __/ /_/ / /_/ __  / /_/ / /_/ / / / / /_/ /
    /_/ /_/ /_/_/   \___/\____/\__/_/ /_/\____/\____/_/ /_/\____/   v.1.0


    Welcome to ThreatHound. Type "help" for a list of commands
    ''')
    # Print banner
    print(text)
    # Get user input
    user_input = input('\n%sThreatHound %s> ' % (GREEN, NORMAL)).lower()

    while len(user_input) >= 0:
        if user_input == "info":
            print(info())
        elif user_input == "help":
            print(get_help())
        elif user_input == "start":
            try:
                sniffer.start_sniffing()
            finally:
                curses.endwin()
        elif (user_input == "exit") or (user_input == "quit") or (user_input == "q"):
            sys.exit()
        elif len(user_input) == 0:
            pass
        else:
            print("\nInvalid Command. Type help for a list of commands\n")
        user_input = input('%sThreatHound %s> ' % (GREEN, NORMAL)).lower()


# Print program banner to the standard output
# It takes "text" as an input parameter
# You can adjust upper/lower lines characters by changing "ch" and "length" default parameters
def banner(text, ch='=', length=560):
    spaced_text = '\n %s \n' % text
    banner = spaced_text.center(length, ch)
    return banner


# Print application INFO page
def info():
    return '''\n
About Threathound:
------------------
ThreatHound v1.0 is a Host Based Intrusion Detection System (HIDS)
written in Python. The software monitors flowing network traffic
and presents alerts in a Command Line-based dashboard. Threathound
plays a role in the early detection and logging of malicious traffic.
Threathound v1.0 doesn't support IPv6 or encrypted traffic.


v1.0 Functionalities:
---------------------
>> Captures/sniffs, interprets and analyzes network traffic
>> Unpacks and analyzes TCP and ICMP traffic to detect anomalies
>> Utilizes YARA rules to identify malicious traffic anomalies
>> Port Monitoring feature
>> Logs detections


Developers:
-----------
belkhoul@emich.edu
mbarazi@emich.edu\n'''


# Check if the Linux user has  root (sudo) privileges
def is_root():
    if os.geteuid() == 0:
        return
    else:
        print('Root Privileges Required!\n Quitting!!!')
        sys.exit()


# Print application help page
def get_help():
    return '''
               ----------------------------------------------------
               |      COMMAND       |            ACTION           |
               ---------------------+------------------------------
               |       help         |   Show this page            |
               ---------------------+------------------------------
               |       info         |   Info about ThreatHound    |
               ---------------------+------------------------------
               |       start        |   Start sniffing            |
               ---------------------+------------------------------
               |     exit/quit      |   Exit Threathound          |
               ----------------------------------------------------

               '''


# Check if the caller will use the program as a module, if not, run "main" function
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n%sInterrupted!!! Exiting hunting mode...%s" % (YELLOW, NORMAL))
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
