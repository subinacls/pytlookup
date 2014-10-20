#!/usr/bin/env python
__author__ = 'William SubINaclS Coppola'
__company__ = "Lares"
__version__ = "20141009"

###
# Python script to automate NSLOOKUP on CIDR ranges
# Kind of lame, but set it and forget it
# Dumps files to disk, already parsed out to have relevant information
###

# basic imports needed for script functionality
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

# set my dafaults
__builtin__.flist = []
__builtin__.rlist = []
__builtin__.c = 0
__builtin__.queue = Queue()
__builtin__.lock = threading.Lock()

# take user arguments, i know its not a variable ...
def takevar():
    __builtin__.trange = str(sys.argv[1]).split(" ;;,.'\"&")[0]  # trying to sanatize user input, i guess ...
    __builtin__.pname = str(sys.argv[2]).split(" ;;,.'\"&")[0]  # trying to sanatize user input, i guess ...
    try:
        if sys.argv[3::]:  # if anything more then 2, error out
            sys.exit()
    except Exception as morearguments:
        #print morearguments, "morearguments"  ## diagnostics
        pass

# make all listed IPs in CIDR - dont care about broad/multicast, route, subnet
def makerlist():
    try:
        #print threading.active_count()   ## diagnostics
        print "\n\t[-] Making IP range list"  ## diagnostics
        if os.path.isfile(trange):  # check if argument is a file
            with open(trange, "r") as timport:  # import IPs from list
                for ip in timport:
                    if str(ip).split("'")[0] not in rlist:
                        rlist.append(str(ip).split("\n")[0])
                    else:  # move onto creating the IP list
                        pass
            print "\n\t\t[!] Testing total ip(s): %s\n" % (str(len(rlist)))  ## diagnostics
        else:
            for ip in IPNetwork(trange):  # make list from CIDR range from argument
                if str(ip).split("'")[0] not in rlist:
                    rlist.append(str(ip).split("'")[0])
                else:  # move on if already in rlist
                    pass
            print "\n\t\t[!] Testing subnet(s): %s - %s\n" % (str(rlist[0]), str(rlist[-1]))  ## diagnostics
        __builtin__.rll = len(rlist)  # get the list length
        #print rll, "rll"  ## diagnostics
        print "\n\t[-] Processing DNS request"  ## diagnostics
    except Exception as failediplist:
        #print failediplist, "failediplist"  ## diagnostics
        pass

# split the list if larger then /24 into more manageable list and file outputs
def splitlist():
    __builtin__.nsl = list(chunks(rlist, 256))  # chunk rlist into individual /24 ranges
    #print nsl

# do the truffle shuffle, actualy logic to chop rlist into subnets
def chunks(l, n):
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

# main threading process logic
def main():
    for x in rnsl:  # for each entry in rlist, spin up a thread
        __builtin__.our_thread1 = threading.Thread(target=pdns)
        our_thread1.start()
    our_thread1.join()  # wait till the end and join all exited threads, makes it faster then individually

# perform the dns query, the process logic
def pdns():
    try:
        nsl = queue.get()  # get new job from queue
        #print nsl  ## diagnostics
        nsplit = str(nsl).split(".")  # split IP into individual Octets
        #print nsplit  ## diagnostics
        #print threading.active_count()  ## diagnostics
        #print "\n\t\t[!] Testing ip: " + str(nsl)+ "\n"  ## diagnostics
        sgfqd = socket.getfqdn(str(nsl))  # this is the actual dns query ;)
        #print sgfqd, "sgfqd"  ## diagnostics
        rsg = re.search("(([0-9]{1,3}\.){3}([0-9]){1,3})", sgfqd)  # strip out IP addresses from results
        if rsg:  # if regex match, this is not the info we are looking for
            pass  # skip
        else:  # if it is the domain name, then process it
            domname = str(sgfqd)  # get the fqdn from the socket
            #print domname, "domain name"  ## diagnostics
            ast = str(nsl) + ", " + str(domname)  # make a perl necklace (IP, DOMAIN)
            #print ast, "ast"
            flist.append(ast)  # append ast to flist (final list)
            #print flist
    except Exception as mpdnsfail:
        #print mpdnsfail, "mdnsfail"  ## diagnostics
        pass

# function to write log files
def wrapitupB(c, flist):  # takes c (count) and list of ip,domain information
    try:
        #print flist, "flist"  ## diagnostics
        fr = flist[0].split(".")  # get the first IP in flist and split individual Octets
        frt= str(fr[0]) + "." + str(fr[1]) + "." + str(fr[2]) + ".0"  # reconstruct to make it a /24 subnet
        if c <= 0:  # check if we have already blanked the original file if it existed
            if os.path.isfile("./"+str(pname)+"_"+str(frt)+"_FQDN.txt"):  # if it was not blanked, do so now
                with open("./"+str(pname)+"_"+str(frt)+"_FQDN.txt", "w") as f:
                    f.write("")
                c = 1  # make it known we have already blanked original file
        # prep to write file
        #print c, "file write counter"  ## diagnostics
        #print "\n\t[-] Writing file: " + "./"+str(pname)+"_"+str(frt)+"_FQDN.txt\n"  ## diagnostics
        #print flist, "flist"
        for xr in flist:  # for each IP in final list
            #print str(xr)  ## diagnostics
            with open("./"+str(pname)+"_"+str(frt)+"_FQDN.txt", "a") as f  # open file and prep for writing
                f.write(str(xr)+str("\n"))
        __builtin__.flist = []  # blank out for new list of subnet results
    except Exception as failedwrite:
        #print failedwrite, "faildwrite"  ## diagnostics
        pass

if __name__ == "__main__":
    try:
        pbar = ProgressBar()  # used to monitor overall process
        takevar()  # take arguments from cli
        makerlist()  # make IP list process
        splitlist()  # split the rlist if needed
        for rnsl in pbar(nsl):  # for each entry in nsl list
            for insl in rnsl:  # for each IP in each entry in rnsl
                #print insl, "insl"  ## diagnostics
                queue.put(insl)  # place a job in the queue
            lock.acquire()  # get lock to prevent stomping
            main()  # run main process to start the threads
            time.sleep(5)  # take a nap, let things finish
            lock.release()  # release lock
            wrapitupB(c, flist)  # write files of returned data
    except Exception as alltuckeredout:  # if all else fails, shit out an error and die
        print alltuckeredout, "altuckeredout"  ## diagnostics
        sys.exit()
