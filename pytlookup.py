#!/usr/bin/env python
__author__ = 'William SubINaclS Coppola'
__company__ = "Lares"
__version__ = "20141009"

###
# Python script to automate NSLOOKUP on CIDR ranges
# Kind of lame, but set it and forget it
# Dumps files to disk, already parsed out to have relevant information
###

# take user arguments
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
        if os.path.isfile(trange):
            with open(trange, "r") as timport:
                for ip in timport:
                    if str(ip).split("'")[0] not in rlist:
                        rlist.append(str(ip).split("\n")[0])
                    else:
                        pass
            print "\n\t\t[!] Testing total ip(s): %s\n" % (str(len(rlist)))  ## diagnostics
        else:
            for ip in IPNetwork(trange):
                if str(ip).split("'")[0] not in rlist:
                    rlist.append(str(ip).split("'")[0])
                else:
                    pass
            print "\n\t\t[!] Testing subnet(s): %s - %s\n" % (str(rlist[0]), str(rlist[-1]))  ## diagnostics

        __builtin__.rll = len(rlist)
        #print rll, "rll"  ## diagnostics
        print "\t[-] Processing DNS request\n"  ## diagnostics
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
        nsl = queue.get()  # get job from queue
        #print nsl  ## diagnostics
        nsplit = str(nsl).split(".")  # split IP on octet
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
            ast = str(nsl) + ", " + str(domname)  # make a perl necklace, string IP and DOMAIN together
            #print ast, "ast"  ## diagnostics
            flist.append(ast)  # append IP, DOMAIN to list
            #print flist, "flist"  ## diagnostics
    except Exception as mpdnsfail:
        #print mpdnsfail, "mdnsfail"  ## diagnostics
        pass

def wrapitupB(c, flist):
    try:
        fr = flist[0].split(".")  # get first IP and break apart the octets
        frt= str(fr[0]) + "." + str(fr[1]) + "." + str(fr[2]) + ".0"  # make a subnet string
        if c <= 0:  # check if counter is 0 or less
            # refresh file if one exist already - no appending duplicate sorting hell
            if os.path.isfile("./"+str(pname)+"_"+str(frt)+"_FQDN.txt"):  # blank contents of any existing files
                with open("./"+str(pname)+"_"+str(frt)+"_FQDN.txt", "w") as f:
                    f.write("")
                c = 1
        # prep to write file
        #print c, "file write counter"
        #print "\n\t[-] Writing file: " + "./"+str(pname)+"_"+str(frt)+"_FQDN.txt\n"  ## diagnostics
        #print flist, "flist"
        with open("./"+str(pname)+"_"+str(frt)+"_FQDN.txt", "a") as f:  # dump data to disk
            for xr in flist:  # for each iteration over items in final list
                #print str(xr)  ## diagnostics
                f.write(str(xr)+str("\n"))
        __builtin__.flist = []  # blank out for new list of subnet results
    except Exception as failedwrite:
        #print failedwrite, "faildwrite"  ## diagnostics
        pass

if __name__ == "__main__":
    try:
        import re
        import os
        import sys
        import time
        import socket
        import __builtin__
        import threading
        from Queue import *
        from netaddr import IPNetwork
        from progressbar import ProgressBar  # might need pip to install progressbar
        # set my blank list
        __builtin__.flist = []  # set to a blank list
        __builtin__.rlist = []  # set to a blank list
        # set up Queue and Locks
        __builtin__.queue = Queue()  # setup Queue for job processing
        __builtin__.lock = threading.Lock()  # setup Lock for process sanatization on shared resources
        # run setup modules
        takevar()  # get user arguments from cli
        makerlist()  # makes the IP list from arguments
        splitlist()  # splits list on 256, appends list to new list
        pbar = ProgressBar()  # used to show progress in application when processing larger list
        for rnsl in pbar(nsl):  # for each list in list
            __builtin__.c = 0  # reset file write counter each list iteration
            for insl in rnsl:  # for each item in list from list
                #print insl, "insl"  ## diagnostics
                queue.put(insl)  # make job queue
            lock.acquire()  # get a lock on job
            main()  # main processing function for thread
            time.sleep(5)  # take a nap, let shit finish up
            wrapitupB(c, flist)  # write files to disk
            lock.release()  # release the lock
    except Exception as alltuckeredout:
        print alltuckeredout, "altuckeredout"  ## diagnostics
        pass
