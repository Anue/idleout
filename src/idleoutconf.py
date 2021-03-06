###################################
#   Idleout configuration file.   #
###################################

# If the user has been idle (or connected) more than "idle" minutes,
# idleout will attempt to kill the processes of this user after "grace" minutes.
# If idle=0, the user is exempt.
# If idle>0, the user must not be idle for to long :) 
# After "grace" minutes, idleout will attempt to kill the user processes.
# If "mail=yes", mail will be sent to the user
#     telling how his processes met its end.
# If "silent=yes" the user will be kicked out without any notification to the screen.

# <<< Log file >>>
log = "/var/log/idleout.log"	
logsize = "5"
# Note: The log size is expressed in megabytes

# <<< Pid file >>>
pid = "/var/run/idleout.pid"

# <<< SMTP Configuration >>>
host = "localhost" 
port = "25"   
domain = "None"

# <<< SESSION - LIMITS >>>

# <<< Group configurations >>>
group = ['admin   idle = 2    grace = 2   mail = no    silent = no',]
# idle=0 -> do not bann users in the manager group!!!

#group = users    idle = 2   grace = 2   mail = no     silent = no
# After 20 minutos of idle time, users in the users group will have 2 minutes of grace.

# <<< User confiturations >>>
name = ['root	idle = 0   grace = 2   mail = no    silent = no',
        'admin	 idle = 2  grace = 2    mail = no    silent = no',
        'marcos   idle = 2  grace = 2    mail = no    silent = no',
        ]
# After 40 minutos of idle time, user "admin" will have 5 minutes of grace.
