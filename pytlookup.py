#!/usr/bin/env python
__author__ = 'William SubINaclS Coppola'
__company__ = "Lares"
__version__ = "20141009"

###
# Python script to automate NSLOOKUP on CIDR ranges
# Kind of lame, but set it and forget it
# Dumps files to disk, already parsed out to have relevant information
###

import re
import os
import sys
import time
import socket
import __builtin__
import threading
from Queue import *
from netaddr import IPNetwork
from progressbar import ProgressBar  ## might need pip to install progressbar

# set my blank list
__builtin__.flist = []
__builtin__.rlist = []
__builtin__.nsl = []
__builtin__.c = 0
__builtin__.queue = Queue()
__builtin__.lock = threading.Lock()

# take user arguments
def takevar():
    __builtin__.trange = sys.argv[1]
    __builtin__.pname = sys.argv[2]

# make all listed IPs in CIDR - dont care about broad/multicast, route, subnet
def makerlist():
    try:
        #print threading.active_count()   ## diagnostics
        print "\n\t[-] Making IP range list"  ## diagnostics
        for ip in IPNetwork(trange):
            if str(ip).split("'")[0] not in rlist:
                rlist.append(str(ip).split("'")[0])
            else:
                pass
        __builtin__.rll = len(rlist)
        #print rll, "rll"  ## diagnostics
        print "\n\t[-] Processing DNS request"  ## diagnostics
        print "\n\t\t[!] Testing subnet(s): %s - %s\n" % (str(rlist[0]), str(rlist[-1]))  ## diagnostics
    except Exception as failediplist:
        #print failediplist, "failediplist"  ## diagnostics
        pass

# split the list if larger then /24 into more manageable list and file outputs
def splitlist():
    __builtin__.nsl = list(chunks(rlist, 256))
    #print nsl

# do the truffle shuffle
def chunks(l, n):
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

# main threading process
def main():
    for x in rnsl:
        __builtin__.our_thread1 = threading.Thread(target=pdns)
        our_thread1.start()
    our_thread1.join()

# perform the dns query
def pdns():
    try:
        nsl = queue.get()
        #print nsl  ## diagnostics
        nsplit = str(nsl).split(".")
        #print nsplit  ## diagnostics
        #print threading.active_count()  ## diagnostics
        #print "\n\t\t[!] Testing ip: " + str(nsl)+ "\n"  ## diagnostics
        sgfqd = socket.getfqdn(str(nsl))  # this is the actual dns query ;)
        #print sgfqd, "sgfqd"  ## diagnostics
        rsg = re.search("(([0-9]{1,3}\.){3}([0-9]){1,3})", sgfqd)  # strip out IP addresses from results
        if rsg:
            pass  # if it is an IP pass on that
        else:
            # get the IP address we checked
            domname = str(sgfqd)  # get the fqdn from the socket
            #print domname, "domain name"  ## diagnostics
            #print ipa, "ip address"  ## diagnostics
            ast = str(nsl) + ", " + str(domname)  # make a perl necklace
            #print ast, "ast"
            flist.append(ast)
            #print flist
    except Exception as mpdnsfail:
        #print mpdnsfail, "mdnsfail"  ## diagnostics
        pass


def wrapitupB(c, flist):
    try:
        #print flist
        fr = flist[0].split(".")
        frt= str(fr[0]) + "." + str(fr[1]) + "." + str(fr[2]) + ".0"
        #frt = str(fr[0])+"_"+str(fr[1])
        if c <= 0:
            # refresh file if one exist already - no appending duplicate sorting hell
            if os.path.isfile("./"+str(pname)+"_"+str(frt)+"_FQDN.txt"):
                with open("./"+str(pname)+"_"+str(frt)+"_FQDN.txt", "w") as f:
                    f.write("")
                c = 1
        # prep to write file
        #print c, "file write counter"
        #print "\n\t[-] Writing file: " + "./"+str(pname)+"_"+str(frt)+"_FQDN.txt\n"  ## diagnostics
        #print flist, "flist"
        for xr in flist:
            #print str(xr)  ## diagnostics
            with open("./"+str(pname)+"_"+str(frt)+"_FQDN.txt", "a") as f:
                f.write(str(xr)+str("\n"))
        __builtin__.flist = []  # blank out for new list of subnet results
    except Exception as failedwrite:
        #print failedwrite, "faildwrite"  ## diagnostics
        pass

if __name__ == "__main__":
    try:
        pbar = ProgressBar()
        takevar()
        makerlist()
        splitlist()
        for rnsl in pbar(nsl):
            for insl in rnsl:
                #print insl, "insl"  ## diagnostics
                queue.put(insl)
            lock.acquire()
            main()
            time.sleep(5)
            lock.release()
            wrapitupB(c, flist)

    except Exception as alltuckeredout:
        print alltuckeredout, "altuckeredout"  ## diagnostics
        pass
