#!/usr/bin/env python2

"""  Marcos Moyano - marcos@anue.biz

 Logout users of a specified period of idle time.

 Copyright (c) 2006 Marcos Moyano

 This program is free software; you can redistribute it and/or modify it
 under the terms of the GNU General Public License version 2 as published by
 the Free Software Foundation.
"""

__author__ = "Marcos Moyano"
__revision__ = "$Id: idleoutd 2013-01-05 $"

import os
import sys
import smtplib
import signal
import subprocess
import argparse
from time import sleep
from configobj import ConfigObj

from logging import fatal, info, warning, DEBUG, getLogger, Formatter
from logging.handlers import RotatingFileHandler

G_FILE = "/etc/group"
P_FILE = "/etc/passwd"
CONFIG_FILE = "/etc/idleout/idleout.conf"

PRINTVERSION = "0.9.0"
PRINTINFO = 0


parser = argparse.ArgumentParser(prog='idleoutd',
                                 description='Parse idleoutd command line options')
parser.add_argument('--debug', '-d',
                    action='store_true', dest='DEBUG',
                    help='Print debug information')
parser.add_argument('--version', '-v', dest='version',
                    action='store_const', const=PRINTVERSION,
                    help='Show version and exist')
parser.add_argument('--conf', '-c', dest='config',
                    action='store',
                    help='Use another configuration file')


##################
# Print Help Msg #
##################
def printhelp():
    """
    Print help information.
    """
    print """Logout users of a specified period of idle time.

Usage: idleoutd [OPTION]

   -D, -d, --debug          Print debug information to the screen every 60 seconds.
   -V, -v, --version        Print version information and exit.
   -h, --help               Print this help and exit.

Report bugs to <marcos@anue.biz>."""
    return

#### End of print help ####

w_tpl = """\n\r\n<<< MESSAGE FROM IDLEOUT >>>\n\n\
\r\tYou have been idle for too long.\n\
\r\tIf you don't send an alive signal in the next {0} minutes you will be kicked out!\n\n\
\r<<<    END OF MESSAGE    >>>\n\n"""

k_tpl = """\n\r\n<<< MESSAGE FROM IDLEOUT >>> \n\n\
\r\tYour {0} minutes has expired.\n\
\r\tKicking out user: {1}\n\n\
\r<<<    END OF MESSAGE    >>>\n\n"""


class Connection(object):
    """A single connection object. Holds information about the user, tty
    device, idle time, connection process and the configuration options
    for that particular user"""
    def __init__(self, user, tty, msg, idle_time, proc, idle_config, grace, silent, mail):
        self.user = user
        self.tty = tty
        self.msg = msg
        self.idle_time = self.parse_time(idle_time)
        self.proc = int(proc)
        self.idle_config = int(idle_config)
        self.grace = int(grace)
        self.silent = silent.lower() == 'yes'
        self.mail = mail.lower() == 'yes'

    def __str__(self):
        return self.__unicode__()

    def __unicode__(self):
        return u"{0} on {1} \t msg:{2} \t idle:{3} \t proc:{4}".format(
            self.user, self.tty, self.msg, self.idle_time, self.proc
        )

    @staticmethod
    def parse_time(t):
        """Given a string like 00:04 representing hours and minutes we
        return the number of minutes (ie: 4)
        """
        return 0 if t == "." else int(t.split(":")[0]) * 60 + int(t.split(":")[1])

    @staticmethod
    def check_smtp(host, port):
        """Check for the SMTP service."""
        try:
            server = smtplib.SMTP(host, port)
        except Exception, err:
            warning("{0} -> Exit code {1} -> Message: {2}".format(
                err.__class__ ,
                err[0], err[1])
            )
            return(1)
        server.quit()
        return(0)

    def writeable(self):
        """Returns True or False if ths connection can receive messages"""
        return self.msg == "+"

    def should_finish(self):
        """Return True if the idle time is longer than t"""
        if self.idle_config == 0: return False
        return self.idle_time >= self.idle_config + self.grace

    def should_warn(self):
        """Return True if the idle time is longer than t"""
        if self.idle_config == 0: return False
        return (self.idle_time > self.idle_config) and (
            self.idle_time < self.idle_config + self.grace
        )

    def email(self, host, port, domain):
        """Send an email to the user about what's going on"""
        if not self.mail: return
        ecode = self.check_smtp(host, port)
        if ecode != 0:
            warning("An SMTP error ocurred. NOT sending email.")
            return
        if domain.lower() != "none":
            toaddrs  = "%s@%s" % (self.user, domain)
            fromaddr = "%s@%s" % ("idleout", domain)
        else:
            toaddrs  = self.user
            fromaddr = "idleout"
        line = """You have been idle for too long.\n\
        Idleout has decided to terminate your conection on device {0}.\n""".format(self.tty)
        msg = "From: {0}\r\nTo: {1}\r\n\r\n{2}".format(fromaddr, toaddrs, line)
        try:
            server = smtplib.SMTP(host, port)
            server.set_debuglevel(0)
            server.sendmail(fromaddr, toaddrs, msg)
            server.quit()
            info("Email sent to user {0}".format(self.user))
        except Exception, err:
            warning("%s -> Exit code %s -> Message: %s" % (err.__class__ , err[0], err[1]))
            warning("An SMTP error ocurred. NOT sending email.")

    def write(self, txt):
        """Write a message to this connection"""
        warning("USER %s idle on DEVICE %s --> NOTIFYING!" % (self.user, self.tty))
        if self.writeable():
            p1 = subprocess.Popen(["echo", txt], stdout=subprocess.PIPE)
            p2 = subprocess.Popen(["write", self.user, self.tty],
                                  stdin=p1.stdout, stdout=subprocess.PIPE)
            p1.stdout.close()
            _, std_err = p2.communicate()
            return std_err
        # Not writeable, let's try to force a message
        try:
            fdr = "/dev/" + self.tty
            tonot = open(fdr,'a')
            tonot.write(txt)
            tonot.close()
        except Exception, err:
            warning("%s -> %s " % (err.__class__ , err))
            warning("I was unable to open device %s." % fdr)

    def terminate(self):
        """Terminate this connection"""
        warning("USER {0} --> timeout on DEVICE {1} --> KICKING OUT!".format(
            self.user, self.tty
        ))
        if not self.silent:
            txt = k_tpl.format(self.grace, self.user)
            self.write(txt)
        try:
            os.kill(self.proc, signal.SIGTERM)
        except OSError:
            os.kill(self.proc, signal.SIGKILL)

    def warn(self):
        """Warn the user about what's going on"""
        if not self.silent:
            txt = w_tpl.format(self.grace)
            self.write(txt)


class ConfigHolder(object):
    """Holds configuration options such as pidfile, smtp, definition
    options and so forth.  Also, it has some helper functions like get
    all the users from a given group or configure the logging system

    """
    def __init__(self, path):
        self.path = path
        self.config = ConfigObj(path)
        self.group = "/etc/group"
        self.passwd = "/etc/passwd"
        self.groups = {}
        self.users = {}
        self.host = self.get('SMTP', 'host')
        self.port = self.get('SMTP', 'port')
        self.domain = self.get('SMTP', 'domain')

    @staticmethod
    def get_time_frame(obj):
        """Return the entire time frame for a configuration option"""
        if obj.get('idle') == 0: return 0
        return obj.get('idle') + obj.get('grace')

    def get(self, section, name=None):
        """"Returns the value of name under section. If no name is
        given, return the entire section"""
        if name:
            return self.config.get(section).get(name)
        return self.config.get(section)

    def config_logger(self):
        logfile = self.get('LOGFILE', 'log')
        logsize = self.get('LOGFILE', 'logsize')
        logger = getLogger('')
        handler = RotatingFileHandler(logfile, 'a', logsize * 1024 * 1024, 10)
        logger.addHandler(handler)
        logger.setLevel(DEBUG)
        formatter = Formatter('%(asctime)s: %(levelname)-8s %(message)s','%b %d %H:%M:%S')
        handler.setFormatter(formatter)

    def get_users_from_group(self, group):
        """Get all the system users from a given group"""
        if group in self.groups:
            return self.groups.get(group)
        groupfile = open(self.group).readlines()
        gid = None
        users = []
        for l in groupfile:
            if l.split(":")[0] == group:
                gid = l.split(":")[2]
                users += l.strip().rsplit(":", 1)[-1].split(",")
                break
        passwordfile = open(self.passwd).readlines()
        for user in passwordfile:
            guid = user.split(":")[3]
            if guid == gid:
                users.append(user.split(":")[0])
        users = list(set(users))
        self.groups[group] = users
        return users

    def config_for_user(self, user):
        """Get configuration options for a given user. Looks for in
        both users and groups.  if there is a user definition, it will
        override any group definition.
        If a user belongs to 2 different groups the lower is returned"""
        if user in self.users:
            return self.users.get(user)
        user_config = self.get('USERS', user)
        if user_config:
            self.users[user] = user_config
            return user_config
        # Check for dup confs and return the lower one (even 0)
        groups = self.config.get('GROUPS').keys()
        gconfig = None
        for group in groups:
            users = self.get_users_from_group(group)
            if user in users:
                tmp_cfg = self.get('GROUPS', group)
                time_frame = self.get_time_frame(tmp_cfg)
                if time_frame == 0:
                    self.users[user] = tmp_cfg
                    return tmp_cfg
                if not gconfig or time_frame < self.get_time_frame(gconfig):
                    gconfig = tmp_cfg
        if gconfig:
            self.users[user] = gconfig
            return gconfig
        return None


class ConnectionHandler(object):
    """Handles all user connections and holds the configuration options"""
    def __init__(self, config_file):
        self.config = config_file
        self.connections = {}
        self.warned = {}

    def __str__(self):
        return self.__unicode__()

    def __unicode__(self):
        return u"{0} connections".format(len(self.connections))

    def add(self, con, warned=False):
        """Add a new connection to the list of connections"""
        if warned:
            self.warned[con.tty] = con
        else:
            self.connections[con.tty] = con

    def update(self, con):
        """Update a warned connection"""
        self.warned[con.tty] = con

    def get_connection(self, tty, warned=False):
        """Get a connection based on the tty device"""
        if warned:
            return self.warned.get(tty, None)
        return self.connections.get(tty, None)

    def already_warned(self, tty):
        """Return True if the tty was already warned"""
        return tty in self.warned

    def remove(self, tty):
        """Remove a given warned connection based on the tty"""
        if tty in self.warned:
            del(self.warned[tty])

    @staticmethod
    def get_system_connections():
        """Get system connections. Returns a list of dictionaries:
        [{'login': login, 'msg': msg, 'tty': tty,
          'idle': idle, 'proc': proc}, ...]"""
        who = subprocess.Popen(['who', '-u', '-w'],
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
        connections = []
        for out in who.stdout:
            login, msg, tty, date, time, idle, proc, comment  = out.strip().split()
            connections.append({'login': login,
                                'msg': msg,
                                'tty': tty,
                                'idle': idle,
                                'proc': proc})
        return connections

    def _split_connections(self):
        """Build three lists of devices.
        remove_ttys: warned connections that should be removed from tracking
        update_ttys: warned connections that should be updated
        new_ttys: new connections found on the system
        """
        ttys = set(self.connections.keys())
        warned_ttys = set(self.warned.keys())
        self.remove_ttys = list(warned_ttys.difference(ttys))
        self.update_ttys = list(ttys & warned_ttys)
        self.new_ttys = list(ttys.difference(warned_ttys))

    def _refresh(self):
        """Refresh the list of all connections"""
        self.connections = {}
        connections = self.get_system_connections()
        for con_info in connections:
            user = con_info.get('login')
            user_config = self.config.config_for_user(user)
            if user_config:
                self.add(Connection(user, con_info.get('tty'), con_info.get('msg'),
                                    con_info.get('idle'), con_info.get('proc'),
                                    user_config.get('idle'),
                                    user_config.get('grace'),
                                    user_config.get('silent'),
                                    user_config.get('mail')))
        self._split_connections()

    def _process(self):
        """Process connections. Warn and/or terminate connections.
        This is the heart and soul of this class"""
        # Warned devices no longer found on the system connections
        # let's get rid of these.
        for tty in self.remove_ttys:
            self.remove(tty)
        # Warned devices found on the system connections.
        # let's update the status.
        for tty in self.update_ttys:
            con = self.get_connection(tty)
            if con.should_finish():
                con.terminate()
                self.remove(tty)
                con.email(self.config.host, self.config.port, self.config.domain)
            else:
                if con.should_warn():
                    self.update(con)
                else:
                    self.remove(tty)
        # New devices found on the system connections.
        # let's see if any of these needs to be warned
        for tty in self.new_ttys:
            con = self.get_connection(tty)
            if con.should_finish():
                con.terminate()
                con.email(self.config.host, self.config.port, self.config.domain)
                continue
            if con.should_warn():
                con.warn()
                self.add(con, warned=True)

    def run(self, debug=False):
        """Run in a loop for ever"""
        while True:
            self._refresh()
            self._process()
            if debug:
                self._show_debug()
            sleep(60)

    def _show_debug(self):
        """Show debugging information"""
        host = self.config.host
        port = self.config.port
        domain = self.config.domain

        print "                  <<<<< DEBUG MODE >>>>> "
        print "---------------------------------------------------------"
        print "      <<< SMTP DIRECTIVES FROM CONFIG FILE >>>\n"
        print ("HOST: {0} --> PORT: {1} --> DOMAIN: {2}".format(host, port, domain))
        print "---------------------------------------------------------"
        print "      <<< USER DIRECTIVES FROM CONFIG FILE >>>"
        for key in self.config.get('USERS').keys():
            print key
            for x, y in self.config.get('USERS', key).items():
                print u"\t{0} = {1}".format(x, y)
        print "---------------------------------------------------------"
        print "      <<< GROUP DIRECTIVES FROM CONFIG FILE >>>"
        for key in self.config.get('GROUPS').keys():
            print key
            for x, y in self.config.get('GROUPS', key).items():
                print u"\t{0} = {1}".format(x, y)
        print "---------------------------------------------------------"
        print "                  <<< CONNECTIONS >>>"
        for tty, con in self.connections.items():
            print("USER: {0} --> DEVICE: {1} --> IDLE TIME: {2}".format(
                con.user, tty, con.idle_time))
        print "\n#########################################################"
        print "            <<< Sleeping for 60 seconds >>> "
        print "#########################################################\n"


if __name__ == "__main__":

    args = parser.parse_args()

    if args.version:
        print ("idleoutd version is: %s \n" % PRINTVERSION)
        sys.exit(0)

    try:
        config_file = args.config if args.config else CONFIG_FILE
        config = ConfigHolder(config_file)
        pidfile = config.get('PIDFILE', 'pid')
        config.config_logger()
    except Exception, err:
        print ("%s -> %s " % (err.__class__ , err))
        sys.exit(1)

    info("<<< Starting Idleout daemon >>>")

    if args.DEBUG:
        info("<<< Idleout daemon started in debug mode >>>")
        try:
            con_handler = ConnectionHandler(config)
            con_handler.run(args.DEBUG)
        except:
            print "Signal caught. Exiting!"
            sys.exit(1)
    else:
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0) # exit first parent
        except OSError, e:
            print >> sys.stderr, "fork 1 failed: %d (%s)" % (e.errno, e.strerror)
            fatal("I was unable to fork into a deamon")
            sys.exit(1)
        try:
            os.chdir("/")
        except Exception, err:
            info("%s -> %s " % (err.__class__ , err))
        try:
            os.setsid()
        except Exception, err:
            info("%s -> %s " % (err.__class__ , err))
        try:
            os.umask(0)
        except Exception, err:
            info("%s -> %s " % (err.__class__ , err))
        try:
            pid = os.fork()
            if pid > 0:
                myfile = open(pidfile, 'w')
                myfile.write(str(pid) + '\n')
                myfile.close()
                info("<<< Idleout daemon started - Pid: %s >>>" % str(pid))
                sys.exit(0)
        except OSError, err:
            print >> sys.stderr, "fork 2 failed: %d: %s" % (err.errno, err.strerror)
            fatal("I was unable to fork into a deamon")
            sys.exit(1)
        # Start the daemon
        try:
            con_handler = ConnectionHandler(config)
            con_handler.run(args.DEBUG)
        except:
            print "Signal caught. Exiting!"
            sys.exit(1)
