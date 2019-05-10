#! /usr/bin/env python
#  Copyright (C) 2013  Sebastian Garcia
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#
# Author:
# Sebastian Garcia eldraco@gmail.com
#
# Changelog

#
# TODO

#
# Description
# Steganoroute is a tool to send steganographed messages to another computer over the network. The receiver must make a traceroute to the sender using the mtr program (and pressing d once to switch the display mode to the continuous graph). This tool, the sender, creates several fake hops and makes them answer the ICMP packets (or not) to write the letters one by one on the mtr client screen.

# Usage:
# Server:
# ./steganoroute.py -i wlan0 -m "Hello World" -l
#
# Client
# mtr -t <server-ip> (and press d after the start)


# standard imports
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
#logging.getLogger("scapy.runtime").setLevel(logging.DEBUG)

import os, pwd, string, sys
try:
    from scapy.all import *
except ImportError:
    print 'You need the python scapy libraries. On debian-based linux type sudo apt-get install python-scapy'
import getopt


####################
# Global Variables

# Debug
debug = 0
vernum = "0.5"
verbose = False
pattern = [] 
lines_deleted = 0
my_ttl = False
my_address = False
negative = False
# Sometimes mtr sends two packets
First_Packet = True
source_address = ""
fake_ip_vect = ['10.0.0.1','10.0.0.2','10.0.0.3','10.0.0.4','10.0.0.5','10.0.0.6','10.0.0.7','10.0.0.8']
# By default do not manage the firewall automatically
manage_firewall = False
# End of global variables
###########################


# Print version information and exit
def version():
  print "+----------------------------------------------------------------------+"
  print "| steganoroute.py Version "+ vernum +"                                      |"
  print "| This program is free software; you can redistribute it and/or modify |"
  print "| it under the terms of the GNU General Public License as published by |"
  print "| the Free Software Foundation; either version 2 of the License, or    |"
  print "| (at your option) any later version.                                  |"
  print "|                                                                      |"
  print "| Author: Garcia Sebastian, eldraco@gmail.com                          |"
  print "| Mateslab Hackspace www.mateslab.com.ar                               |"
  print "+----------------------------------------------------------------------+"
  print


# Print help information and exit:
def usage():
  print "+----------------------------------------------------------------------+"
  print "| steganoroute.py Version "+ vernum +"                                      |"
  print "| This program is free software; you can redistribute it and/or modify |"
  print "| it under the terms of the GNU General Public License as published by |"
  print "| the Free Software Foundation; either version 2 of the License, or    |"
  print "| (at your option) any later version.                                  |"
  print "|                                                                      |"
  print "| Author: Garcia Sebastian, eldraco@gmail.com                          |"
  print "| Mateslab Hackspace www.mateslab.com.ar                               |"
  print "+----------------------------------------------------------------------+"
  print "\nusage: %s <options>" % sys.argv[0]
  print "options:"
  print "  -h, --help         	Show this help message and exit"
  print "  -V, --version      	Output version information and exit"
  print "  -v, --verbose      	Output more information."
  print "  -D, --debug      	Debug."
  print "  -m, --message    	Message to send."
  print "  -i, --interface    	Interface to use."
  print "  -n, --negative    	Photographic Negative version. Use packets for the letters instead of timeouts."
  print "  -l, --loop      	Loop forever."
  print "  -t, --ttl      	The first TTL this computer should respond to. By default it is the TTL of the first packet it sniffs."
  print "  -a, --address      	Sniff packets arriving at this IP address only. To avoid problems with outgoing mtr from the server!"
  print "  -s, --source      	Send messages only to this client source address."
  print "  -c, --conspiracy    Conspiracy mode. Use the IP addresses of real intelligence agencies as fake hops. It seams that every agency is doing a MITM to you!"
  print "  -f, --firewall    Manage the firewall for me. This option automatically adds a rule to stop your computer from receiving pings and deletes it on exit. If you do not use this option you MUST stop your computer from receiving pings by hand. Use this to put the rule : 'iptables -D INPUT 1 -p icmp --icmp-type 8 -j DROP' and this to delete the rule 'iptables -D INPUT 1'"
  print
  sys.exit(1)




def create_message(message):
    """ 
    Create the message from the letters to the vectors of logic
    """
    global debug
    global verbose
    global debug
    global pattern
    global manage_firewall

    try:
        if debug:
            print 'Message to send: ' + str(message)

        A_letter = [[0,0,1,1,1,1,1,0],  
                    [0,1,0,0,1,0,0,0],  
                    [0,1,0,0,1,0,0,0],  
                    [0,1,0,0,1,0,0,0],  
                    [0,1,0,0,1,0,0,0],  
                    [0,0,1,1,1,1,1,0],
                    [0,0,0,0,0,0,0,0]]

        B_letter = [[0,1,1,1,1,1,1,0],  
                    [0,1,0,1,0,0,1,0],  
                    [0,1,0,1,0,0,1,0],  
                    [0,1,0,1,0,0,1,0],  
                    [0,1,0,1,0,0,0,0],  
                    [0,0,1,0,1,1,0,0],
                    [0,0,0,0,0,0,0,0]]

        C_letter = [[0,0,1,1,1,1,0,0],  
                    [0,1,0,0,0,0,1,0],  
                    [0,1,0,0,0,0,1,0],  
                    [0,1,0,0,0,0,1,0],  
                    [0,1,0,0,0,0,1,0],  
                    [0,0,1,0,0,1,0,0],
                    [0,0,0,0,0,0,0,0]]

        D_letter = [[0,1,1,1,1,1,1,0],  
                    [0,1,0,0,0,0,1,0],  
                    [0,1,0,0,0,0,1,0],  
                    [0,1,0,0,0,0,1,0],  
                    [0,0,1,0,0,1,0,0],  
                    [0,0,0,1,1,0,0,0],
                    [0,0,0,0,0,0,0,0]]

        E_letter = [[0,1,1,1,1,1,1,0],  
                    [0,1,0,1,0,0,1,0],  
                    [0,1,0,1,0,0,1,0],  
                    [0,1,0,1,0,0,1,0],  
                    [0,1,0,1,0,0,1,0],  
                    [0,1,0,0,0,0,1,0],
                    [0,0,0,0,0,0,0,0]]

        F_letter = [[0,1,1,1,1,1,1,0],  
                    [0,1,0,1,0,0,0,0],  
                    [0,1,0,1,0,0,0,0],  
                    [0,1,0,1,0,0,0,0],  
                    [0,1,0,0,0,0,0,0],  
                    [0,1,0,0,0,0,0,0],
                    [0,0,0,0,0,0,0,0]]

        G_letter = [[0,0,1,1,1,1,0,0],  
                    [0,1,0,0,0,0,1,0],  
                    [0,1,0,0,0,0,1,0],  
                    [0,1,0,0,0,0,1,0],  
                    [0,1,0,0,1,0,1,0],  
                    [0,0,1,0,1,1,0,0],
                    [0,0,0,0,0,0,0,0]]

        H_letter = [[0,1,1,1,1,1,1,0],  
                    [0,0,0,1,0,0,0,0],  
                    [0,0,0,1,0,0,0,0],  
                    [0,0,0,1,0,0,0,0],  
                    [0,0,0,1,0,0,0,0],  
                    [0,1,1,1,1,1,1,0],
                    [0,0,0,0,0,0,0,0]]

        I_letter = [[0,1,0,0,0,0,1,0],  
                    [0,1,0,0,0,0,1,0],  
                    [0,1,0,0,0,0,1,0],  
                    [0,1,1,1,1,1,1,0],  
                    [0,1,0,0,0,0,1,0],  
                    [0,1,0,0,0,0,1,0],
                    [0,1,0,0,0,0,1,0],
                    [0,0,0,0,0,0,0,0]]

        J_letter = [[0,0,0,0,1,1,0,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,1,1,1,1,1,0,0],
                    [0,0,0,0,0,0,0,0]]

        K_letter = [[0,1,1,1,1,1,1,0],  
                    [0,0,0,1,0,0,0,0],  
                    [0,0,0,1,0,0,0,0],  
                    [0,0,1,0,1,0,0,0],  
                    [0,1,0,0,0,1,0,0],  
                    [0,0,0,0,0,0,1,0],
                    [0,0,0,0,0,0,0,0]]

        L_letter = [[0,1,1,1,1,1,1,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,0,1,0],
                    [0,0,0,0,0,0,0,0]]

        M_letter = [[0,1,1,1,1,1,1,0],  
                    [0,0,1,0,0,0,0,0],  
                    [0,0,0,1,0,0,0,0],  
                    [0,0,0,1,0,0,0,0],  
                    [0,0,1,0,0,0,0,0],  
                    [0,1,1,1,1,1,1,0],
                    [0,0,0,0,0,0,0,0]]

        N_letter = [[0,1,1,1,1,1,1,0],  
                    [0,0,1,0,0,0,0,0],  
                    [0,0,0,1,0,0,0,0],  
                    [0,0,0,0,1,0,0,0],  
                    [0,0,0,0,0,1,0,0],  
                    [0,1,1,1,1,1,1,0],
                    [0,0,0,0,0,0,0,0]]


        O_letter = [[0,0,1,1,1,1,0,0],  
                    [0,1,0,0,0,0,1,0],  
                    [0,1,0,0,0,0,1,0],  
                    [0,1,0,0,0,0,1,0],  
                    [0,1,0,0,0,0,1,0],  
                    [0,0,1,1,1,1,0,0],
                    [0,0,0,0,0,0,0,0]]

        P_letter = [[0,1,1,1,1,1,1,0],  
                    [0,1,0,0,1,0,0,0],  
                    [0,1,0,0,1,0,0,0],  
                    [0,1,0,0,1,0,0,0],  
                    [0,1,0,0,1,0,0,0],  
                    [0,0,1,1,0,0,0,0],
                    [0,0,0,0,0,0,0,0]]

        Q_letter = [[0,0,1,1,1,1,0,0],  
                    [0,1,0,0,0,0,1,0],  
                    [0,1,0,0,0,0,1,0],  
                    [0,1,0,0,1,0,1,0],  
                    [0,1,0,0,0,1,1,0],  
                    [0,0,1,1,1,1,0,0],
                    [0,0,0,0,0,0,0,0]]

        R_letter = [[0,1,1,1,1,1,1,0],  
                    [0,1,0,0,1,0,0,0],  
                    [0,1,0,0,1,0,0,0],  
                    [0,1,0,0,1,0,0,0],  
                    [0,1,0,0,1,1,0,0],  
                    [0,0,1,1,0,0,1,0],
                    [0,0,0,0,0,0,0,0]]

        S_letter = [[0,0,1,0,0,1,0,0],  
                    [0,1,0,1,0,0,0,0],  
                    [0,1,0,1,0,0,1,0],  
                    [0,1,0,1,0,0,1,0],  
                    [0,1,0,1,0,0,1,0],  
                    [0,0,0,0,1,1,0,0],
                    [0,0,0,0,0,0,0,0]]

        T_letter = [[0,1,0,0,0,0,0,0],  
                    [0,1,0,0,0,0,0,0],  
                    [0,1,0,0,0,0,0,0],  
                    [0,1,1,1,1,1,1,0],  
                    [0,1,0,0,0,0,0,0],  
                    [0,1,0,0,0,0,0,0],
                    [0,1,0,0,0,0,0,0],
                    [0,0,0,0,0,0,0,0]]

        U_letter = [[0,1,1,1,1,1,0,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,1,1,1,1,1,0,0],
                    [0,0,0,0,0,0,0,0]]

        V_letter = [[0,1,1,1,1,0,0,0],  
                    [0,0,0,0,0,1,0,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,1,0,0],  
                    [0,1,1,1,1,0,0,0],
                    [0,0,0,0,0,0,0,0]]

        W_letter = [[0,1,1,1,1,1,0,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,1,0,0],  
                    [0,0,0,0,0,1,0,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,1,1,1,1,1,0,0],
                    [0,0,0,0,0,0,0,0]]

        X_letter = [[0,1,0,0,0,0,1,0],  
                    [0,0,1,0,0,1,0,0],  
                    [0,0,0,1,1,0,0,0],  
                    [0,0,0,1,1,0,0,0],  
                    [0,0,1,0,0,1,0,0],  
                    [0,1,0,0,0,0,1,0],
                    [0,0,0,0,0,0,0,0]]

        Y_letter = [[0,1,0,0,0,0,0,0],  
                    [0,0,1,0,0,0,0,0],  
                    [0,0,0,1,0,0,0,0],  
                    [0,0,0,0,1,1,1,0],  
                    [0,0,0,1,0,0,0,0],  
                    [0,0,1,0,0,0,0,0],
                    [0,1,0,0,0,0,0,0],
                    [0,0,0,0,0,0,0,0]]

        Z_letter = [[0,1,0,0,0,0,1,0],  
                    [0,1,0,0,0,1,1,0],  
                    [0,1,0,0,1,0,1,0],  
                    [0,1,0,1,0,0,1,0],  
                    [0,1,1,0,0,0,1,0],  
                    [0,1,0,0,0,0,1,0],
                    [0,0,0,0,0,0,0,0]]

        a_letter = [[0,0,0,0,0,1,0,0],  
                    [0,0,1,0,1,0,1,0],  
                    [0,0,1,0,1,0,1,0],  
                    [0,0,1,0,1,0,1,0],  
                    [0,0,0,1,1,1,1,0],  
                    [0,0,0,0,0,0,0,0]]

        b_letter = [[0,1,1,1,1,1,1,0],  
                    [0,0,0,1,0,0,1,0],  
                    [0,0,0,1,0,0,1,0],  
                    [0,0,0,1,0,0,1,0],  
                    [0,0,0,0,1,1,0,0],  
                    [0,0,0,0,0,0,0,0]]

        c_letter = [[0,0,0,1,1,1,0,0],  
                    [0,0,1,0,0,0,1,0],  
                    [0,0,1,0,0,0,1,0],  
                    [0,0,1,0,0,0,1,0],  
                    [0,0,0,0,0,0,0,0]]

        d_letter = [[0,0,0,0,1,1,0,0],  
                    [0,0,0,1,0,0,1,0],  
                    [0,0,0,1,0,0,1,0],  
                    [0,0,0,1,0,0,1,0],  
                    [0,1,1,1,1,1,1,0],  
                    [0,0,0,0,0,0,0,0]]

        e_letter = [[0,0,0,1,1,1,0,0],  
                    [0,0,1,0,1,0,1,0],  
                    [0,0,1,0,1,0,1,0],  
                    [0,0,1,0,1,0,1,0],  
                    [0,0,0,1,0,0,1,0],  
                    [0,0,0,0,0,0,0,0]]

        f_letter = [[0,0,1,1,1,1,1,0],  
                    [0,1,0,1,0,0,0,0],  
                    [0,1,0,0,0,0,0,0],  
                    [0,0,0,0,0,0,0,0]]

        g_letter = [[0,0,0,1,1,0,0,0],  
                    [0,0,1,0,0,1,0,1],  
                    [0,0,1,0,0,1,0,1],  
                    [0,0,1,0,0,1,0,1],  
                    [0,0,1,1,1,1,1,0],  
                    [0,0,0,0,0,0,0,0]]

        h_letter = [[0,1,1,1,1,1,1,0],  
                    [0,0,0,1,0,0,0,0],  
                    [0,0,0,1,0,0,0,0],  
                    [0,0,0,1,0,0,0,0],  
                    [0,0,0,0,1,1,1,0],  
                    [0,0,0,0,0,0,0,0]]

        i_letter = [[0,0,0,1,0,0,1,0],  
                    [0,1,0,1,1,1,1,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,0,0,0]]

        j_letter = [[0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,0,0,1],  
                    [0,0,0,0,0,0,0,1],  
                    [0,1,0,1,1,1,1,0],  
                    [0,0,0,0,0,0,0,0]]

        k_letter = [[0,1,1,1,1,1,1,0],  
                    [0,0,0,1,1,0,0,0],  
                    [0,0,1,0,0,1,0,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,0,0,0]]

        l_letter = [[0,1,1,1,1,1,0,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,0,1,0],
                    [0,0,0,0,0,0,0,0]]

        m_letter = [[0,0,1,1,1,1,1,0],  
                    [0,0,1,0,0,0,0,0],  
                    [0,0,0,1,1,1,1,0],  
                    [0,0,1,0,0,0,0,0],  
                    [0,0,0,1,1,1,1,0],  
                    [0,0,0,0,0,0,0,0]]

        n_letter = [[0,0,1,1,1,1,1,0],  
                    [0,0,1,0,0,0,0,0],  
                    [0,0,1,0,0,0,0,0],  
                    [0,0,1,0,0,0,0,0],  
                    [0,0,0,1,1,1,1,0],  
                    [0,0,0,0,0,0,0,0]]

        o_letter = [[0,0,0,1,1,1,0,0],  
                    [0,0,1,0,0,0,1,0],  
                    [0,0,1,0,0,0,1,0],  
                    [0,0,1,0,0,0,1,0],  
                    [0,0,0,1,1,1,0,0],  
                    [0,0,0,0,0,0,0,0]]

        p_letter = [[0,0,1,1,1,1,1,1],  
                    [0,0,1,0,0,1,0,0],  
                    [0,0,1,0,0,1,0,0],  
                    [0,0,1,0,0,1,0,0],  
                    [0,0,0,1,1,0,0,0],  
                    [0,0,0,0,0,0,0,0]]


        q_letter = [[0,0,0,1,1,0,0,0],  
                    [0,0,1,0,0,1,0,0],  
                    [0,0,1,0,0,1,0,0],  
                    [0,0,1,0,0,1,0,0],  
                    [0,0,1,1,1,1,1,1],  
                    [0,0,0,0,0,0,0,1],  
                    [0,0,0,0,0,0,0,0]]

        r_letter = [[0,0,0,1,1,1,1,0],  
                    [0,0,1,0,0,0,0,0],  
                    [0,0,1,0,0,0,0,0],  
                    [0,0,1,0,0,0,0,0],  
                    [0,0,0,0,0,0,0,0]]

        s_letter = [[0,0,0,1,0,0,1,0],  
                    [0,0,1,0,1,0,1,0],  
                    [0,0,1,0,1,0,1,0],  
                    [0,0,1,0,1,0,1,0],  
                    [0,0,0,0,0,1,0,0],  
                    [0,0,0,0,0,0,0,0]]

        t_letter = [[0,0,1,0,0,0,0,0],  
                    [0,1,1,1,1,1,0,0],  
                    [0,0,1,0,0,0,1,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,0,0,0],  
                    [0,0,0,0,0,0,0,0]]

        u_letter = [[0,0,1,1,1,1,0,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,1,1,1,1,0,0],  
                    [0,0,0,0,0,0,0,0]]

        v_letter = [[0,0,1,1,0,0,0,0],  
                    [0,0,0,0,1,1,0,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,0,1,1,0,0],  
                    [0,0,1,1,0,0,0,0],  
                    [0,0,0,0,0,0,0,0]]

        w_letter = [[0,0,1,1,1,1,0,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,0,1,1,1,0,0],  
                    [0,0,0,0,0,0,1,0],  
                    [0,0,1,1,1,1,0,0],  
                    [0,0,0,0,0,0,0,0]]

        x_letter = [[0,0,1,0,0,0,1,0],  
                    [0,0,0,1,0,1,0,0],  
                    [0,0,0,0,1,0,0,0],  
                    [0,0,0,1,0,1,0,0],  
                    [0,0,1,0,0,0,1,0],  
                    [0,0,0,0,0,0,0,0]]

        y_letter = [[0,0,1,1,1,0,0,0],  
                    [0,0,0,0,0,1,0,1],  
                    [0,0,0,0,0,1,0,1],  
                    [0,0,0,0,0,1,0,1],  
                    [0,0,1,1,1,1,1,0],  
                    [0,0,0,0,0,0,0,0]]

        z_letter = [[0,0,1,0,0,0,1,0],  
                    [0,0,1,0,0,1,1,0],  
                    [0,0,1,0,1,0,1,0],  
                    [0,0,1,1,0,0,1,0],  
                    [0,0,1,0,0,0,1,0],  
                    [0,0,0,0,0,0,0,0]]

        space_letter = [[0,0,0,0,0,0,0,0],  
                        [0,0,0,0,0,0,0,0]]

        letters = {}
        # Upper case
        letters['A'] = A_letter
        letters['B'] = B_letter
        letters['C'] = C_letter
        letters['D'] = D_letter
        letters['E'] = E_letter
        letters['F'] = F_letter
        letters['G'] = G_letter
        letters['H'] = H_letter
        letters['I'] = I_letter
        letters['J'] = J_letter
        letters['K'] = K_letter
        letters['L'] = L_letter
        letters['M'] = M_letter
        letters['N'] = N_letter
        letters['O'] = O_letter
        letters['P'] = P_letter
        letters['Q'] = Q_letter
        letters['R'] = R_letter
        letters['S'] = S_letter
        letters['T'] = T_letter
        letters['U'] = U_letter
        letters['V'] = V_letter
        letters['W'] = W_letter
        letters['X'] = X_letter
        letters['Y'] = Y_letter
        letters['Z'] = Z_letter
        # Lower case
        letters['a'] = a_letter
        letters['b'] = b_letter
        letters['c'] = c_letter
        letters['d'] = d_letter
        letters['e'] = e_letter
        letters['f'] = f_letter
        letters['g'] = g_letter
        letters['h'] = h_letter
        letters['i'] = i_letter
        letters['j'] = j_letter
        letters['k'] = k_letter
        letters['l'] = l_letter
        letters['m'] = m_letter
        letters['n'] = n_letter
        letters['o'] = o_letter
        letters['p'] = p_letter
        letters['q'] = q_letter
        letters['r'] = r_letter
        letters['s'] = s_letter
        letters['t'] = t_letter
        letters['u'] = u_letter
        letters['v'] = v_letter
        letters['w'] = w_letter
        letters['x'] = x_letter
        letters['y'] = y_letter
        letters['z'] = z_letter
        letters[' '] = space_letter


        # Add the start pattern
        pattern = [ [1,1,1,1,1,1,1,1,1], 
                    [0,0,0,0,0,0,0,0,0]]

        for letter in message:
            if debug:
                print 'Processing letter: {0}'.format(letter)
            for i in letters[letter]:
                pattern.append(i)

        # Add the end pattern
        pattern += [ [0,0,0,0,0,0,0,0,0], 
                    [0,0,0,0,0,0,0,0,0],
                    [0,0,0,0,0,0,0,0,0]]


        if debug:
            print 'Len of the pattern : {0}'.format(len(pattern))


    except Exception as inst:
        if debug:
            print '\tProblem in ()'
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to printed directly
        x, y = inst          # __getitem__ allows args to be unpacked directly
        print 'x =', x
        print 'y =', y
        if manage_firewall:
            # Before going out, put everything in place again...
            iptables_command = "iptables -D INPUT 1"
            os.system(iptables_command)
        exit(-1)




def send_message(interface):
    """ 
    Sniff and process packets.
    """
    global debug
    global verbose
    global debug
    global my_address
    global source_address
    global manage_firewall

    try:
        filter_text = "icmp[0]=8 and icmp[8] < 40"
        
        print 'Sniffing packets and sending text in this round...'
        # The filter is to catch only traceroute packets. That is packets with TTL < 30.
        if not my_address and source_address:
            filter_text = filter_text + " and src host " + source_address
        elif my_address and not source_address:
            filter_text = filter_text + " and dst host " + my_address
        elif my_address and source_address:
            filter_text = filter_text + " and dst host " + my_address + " and src host " + source_address
        
        if debug:
            print 'Filter text applied: {0}'.format(filter_text)

        try:
            pkts = sniff(count=0,filter=filter_text,prn=lambda x:process_packet(len(x),x),iface=interface)               
        except socket.error:
            print 'You need to be root to sniff packets.'

    except Exception as inst:
        if debug:
            print '\tProblem in send_message()'
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to printed directly
        x, y = inst          # __getitem__ allows args to be unpacked directly
        print 'x =', x
        print 'y =', y
        if manage_firewall:
            # Before going out, put everything in place again...
            iptables_command = "iptables -D INPUT 1"
            os.system(iptables_command)
        exit(-1)



def process_packet(pkt_len,pkt):
    """
    Process each packet and send the packets.
    """
    global debug
    global verbose
    global pattern
    global my_ttl
    global inverse
    global lines_deleted
    global First_Packet
    global fake_ip_vect

    try:

        # If the user did not give any ttl, use the one in the first packet you see.
        if not my_ttl:
            my_ttl = pkt[IP].ttl

        current_ttl = pkt[IP].ttl
        if verbose:
            print
            print 'Packet received from {0}. TTL:{1} (myttl:{2}). '.format(pkt[IP].src,str(current_ttl), str(my_ttl)),

        if current_ttl == my_ttl:
            First_Packet = True
            # The lines_deleted==0 part is to force the program to answer with a packet the first time.
            if (pattern[0][0] == negative) or (lines_deleted==0):
                resp_ip = IP(src=fake_ip_vect[0], dst=pkt[IP].src)
                resp_icmp = ICMP(type=11, code=0 ,id=hex(pkt[ICMP].id), seq=pkt[ICMP].seq)
                send(resp_ip/resp_icmp/pkt[0].payload,verbose=0)
                if verbose and not debug:
                    print ' Packet send.',
                elif debug:
                    print ' Packet send: {0} {1}'.format(resp_ip.summary(),resp_icmp.summary()),

        elif current_ttl == my_ttl + 1 :
            First_Packet = True
            if (pattern[0][1] == negative) or (lines_deleted==0):
                resp_ip = IP(src=fake_ip_vect[1], dst=pkt[IP].src)
                resp_icmp = ICMP(type=11, code=0 ,id=hex(pkt[ICMP].id), seq=pkt[ICMP].seq)
                send(resp_ip/resp_icmp/pkt[0].payload,verbose=0)
                if verbose and not debug:
                    print ' Packet send.',
                elif debug:
                    print ' Packet send: {0} {1}'.format(resp_ip.summary(),resp_icmp.summary()),

        elif current_ttl == my_ttl + 2 :
            First_Packet = True
            if (pattern[0][2] == negative) or (lines_deleted==0):
                resp_ip = IP(src=fake_ip_vect[2], dst=pkt[IP].src)
                resp_icmp = ICMP(type=11, code=0 ,id=hex(pkt[ICMP].id), seq=pkt[ICMP].seq)
                send(resp_ip/resp_icmp/pkt[0].payload,verbose=0)
                if verbose and not debug:
                    print ' Packet send.',
                elif debug:
                    print ' Packet send: {0} {1}'.format(resp_ip.summary(),resp_icmp.summary()),

        elif current_ttl == my_ttl + 3 :
            First_Packet = True
            if (pattern[0][3] == negative) or (lines_deleted==0):
                resp_ip = IP(src=fake_ip_vect[3], dst=pkt[IP].src)
                resp_icmp = ICMP(type=11, code=0 ,id=hex(pkt[ICMP].id), seq=pkt[ICMP].seq)
                send(resp_ip/resp_icmp/pkt[0].payload,verbose=0)
                if verbose and not debug:
                    print ' Packet send.',
                elif debug:
                    print ' Packet send: {0} {1}'.format(resp_ip.summary(),resp_icmp.summary()),

        elif current_ttl == my_ttl + 4 :
            First_Packet = True
            if (pattern[0][4] == negative) or (lines_deleted==0):
                resp_ip = IP(src=fake_ip_vect[4], dst=pkt[IP].src)
                resp_icmp = ICMP(type=11, code=0 ,id=hex(pkt[ICMP].id), seq=pkt[ICMP].seq)
                send(resp_ip/resp_icmp/pkt[0].payload,verbose=0)
                if verbose and not debug:
                    print ' Packet send.',
                elif debug:
                    print ' Packet send: {0} {1}'.format(resp_ip.summary(),resp_icmp.summary()),

        elif current_ttl == my_ttl + 5 :
            First_Packet = True
            if (pattern[0][5] == negative) or (lines_deleted==0):
                resp_ip = IP(src=fake_ip_vect[5], dst=pkt[IP].src)
                resp_icmp = ICMP(type=11, code=0 ,id=hex(pkt[ICMP].id), seq=pkt[ICMP].seq)
                send(resp_ip/resp_icmp/pkt[0].payload,verbose=0)
                if verbose and not debug:
                    print ' Packet send.',
                elif debug:
                    print ' Packet send: {0} {1}'.format(resp_ip.summary(),resp_icmp.summary()),

        elif current_ttl == my_ttl + 6 :
            First_Packet = True
            if (pattern[0][6] == negative) or (lines_deleted==0):
                resp_ip = IP(src=fake_ip_vect[6], dst=pkt[IP].src)
                resp_icmp = ICMP(type=11, code=0 ,id=hex(pkt[ICMP].id), seq=pkt[ICMP].seq)
                send(resp_ip/resp_icmp/pkt[0].payload,verbose=0)
                if verbose and not debug:
                    print ' Packet send.',
                elif debug:
                    print ' Packet send: {0} {1}'.format(resp_ip.summary(),resp_icmp.summary()),

        elif current_ttl == my_ttl + 7 :
            First_Packet = True
            if (pattern[0][7] == negative) or (lines_deleted==0):
                resp_ip = IP(src=fake_ip_vect[7], dst=pkt[IP].src)
                resp_icmp = ICMP(type=11, code=0 ,id=hex(pkt[ICMP].id), seq=pkt[ICMP].seq)
                send(resp_ip/resp_icmp/pkt[0].payload,verbose=0)
                if verbose and not debug:
                    print ' Packet send.',
                elif debug:
                    print ' Packet send: {0} {1}'.format(resp_ip.summary(),resp_icmp.summary()),

        elif current_ttl == my_ttl + 8 :
                try:
                    if First_Packet:
                        if verbose:
                            print ' Last hop. Changing pattern.',
                        pattern = pattern[1:]
                        lines_deleted = lines_deleted + 1
                        if len(pattern)==0:
                            raise KeyboardInterrupt
                        First_Packet = False
                    elif not First_Packet:
                        First_Packet = True
                except Exception as inst:
                    print 'Exception in process_packet() function'
                    print type(inst)     # the exception instance
                    print inst.args      # arguments stored in .args
                    print inst           # __str__ allows args to printed directly


    except IndexError:
        if debug:
            print 'List index out of range.'
        return

    except Exception as inst:
        print 'Exception in process_packet() function'
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to printed directly



		


def main():
    try:
        global debug
        global verbose
        global negative
        global my_ttl
        global my_address
        global source_address
        global fake_ip_vect
        global manage_firewall

        message = ''
        interface = 'wlan0'
        loop=False
        conspiracy = False

        opts, args = getopt.getopt(sys.argv[1:], "a:cfhVvDm:i:nls:t:", ["address=", "conspiracy", "firewall" , "help","version","verbose","debug", "message", "interface", "negative", "loop", "source=", "ttl="])
    except getopt.GetoptError: usage()

    for opt, arg in opts:
        if opt in ("-h", "--help"): usage()
        if opt in ("-V", "--version"): version();exit(-1)
        if opt in ("-v", "--verbose"): verbose=True
        if opt in ("-D", "--debug"): debug=1; verbose=True
        if opt in ("-m", "--message"): message=str(arg)
        if opt in ("-i", "--interface"): interface=str(arg)
        if opt in ("-n", "--negative"): negative = True
        if opt in ("-l", "--loop"): loop = True
        if opt in ("-t", "--ttl"): my_ttl = int(arg)
        if opt in ("-a", "--address"): my_address = str(arg)
        if opt in ("-s", "--source"): source_address = str(arg)
        if opt in ("-c", "--conspiracy"): conspiracy = True
        if opt in ("-f", "--firewall"): manage_firewall = True
    try:

        try:
            if message == "":
                usage()
                sys.exit(1)
            else:
                # We have everything, just go on...
                print

                if manage_firewall:
                    # Avoid being pinged during our operation...
                    iptables_command = "iptables -I INPUT 1 -p icmp -d 192.168.0.8 --icmp-type 8 -j DROP"
                    os.system(iptables_command)
                else:
                    print 'Remember to stop your computer from receving pings!! Otherwise it won\'t work. Use iptables -D INPUT 1 -p icmp --icmp-type 8 -j DROP'

                if conspiracy:
                    fake_ip_vect = ['194.61.183.121','198.81.129.68','156.154.64.48','212.77.0.110','87.106.27.103','203.119.25.1','198.117.1.122','193.140.100.28']

                create_message(message)
                if loop:
                    while True:
                        send_message(interface)
                        create_message(message)
                else:
                    send_message(interface)

                if manage_firewall:
                    # Before going out, put everything in place again...
                    iptables_command = "iptables -D INPUT 1"
                    os.system(iptables_command)

        except Exception, e:
            print "misc. exception (runtime error from user callback?):", e
        except KeyboardInterrupt:
            if manage_firewall:
                # Before going out, put everything in place again...
                iptables_command = "iptables -D INPUT 1"
                os.system(iptables_command)
            sys.exit(1)


    except KeyboardInterrupt:
        # CTRL-C pretty handling.
        print "Keyboard Interruption!. Exiting."
        if manage_firewall:
            # Before going out, put everything in place again...
            iptables_command = "iptables -D INPUT 1"
            os.system(iptables_command)
        sys.exit(1)


if __name__ == '__main__':
    main()
