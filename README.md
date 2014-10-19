pytlookup
=========

python implementation of NSLOOKUP using socket.getfqdn() in a threaded Queued make for a faster lookup speed
uses locks to prevent other Queues from stepping on current running thread

dumps all returned domain names to repective subnet file broken on the /24 (256) IP's

example command:

    ./pytlookup.py 10.1.0.0/16 internal_10-1_classB  # using a CIDR range of IP's
    ./pytlookup.py somefile.txt internal_10-1_classB  # using a file of IP's
    ./<Script> <List/CIDR> <Project Name>
    
All files are stored in the CWD() where script is launced. It is recommended to launch this in the directory you plan to store them.

If there is currently a file which would match the name produced, the script will blank the original file
and then append all the informaiton to this file. In other words, data can and will be stomped on if it exist.

Best idea for this if your using this across the same range over different quarters or yearly, change the project name to be unique
