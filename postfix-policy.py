#!/usr/bin/env python

import asyncore, socket, sqlite3, time, syslog, sys, os, signal

'''
Settings go here
'''
action_reject_distributed_detect = "action=REJECT Message rejected - conspicuous relay pattern - contact your administrator\n\n"
action_reject_quota = "action=defer_if_permit Message rejected - account over quota - contact your administrator\n\n"
action_ok = "action=PREPEND SMTP-policy: ok\n\n"

bind_ip = "0.0.0.0"
port = 10032

database = ":memory:"
flush_database = "postfix-policy.db"

# use distributed relay detect
distributed_relay_detect = True
distributed_relay_detect_release_time = 1800 
distributed_relay_detect_max_hosts = 2 # set this to a reasonable value (many users have more than one device!)

# use throtteling
throttle = True
throttle_max_msg=1000
throttle_release_time = 3600

# use whitelisting
whitelist = False

'''
Settings end here
'''

try:
    conn = sqlite3.connect(database)
except:
    exit

class PolicyServer(asyncore.dispatcher):
    def __init__(self, host, port):
        global conn
        c=conn.cursor()
        try:
            if(os.path.exists(flush_database)):
                # import the flushed database to our work db (which should be :memory:)
                import_db=sqlite3.connect(flush_database)
                import_query="".join(line for line in import_db.iterdump())
                conn.executescript(import_query)
            else:
                c.execute('''CREATE TABLE distributed_relay_detect (sasl_username text,client_address text,sender text,time_created bigint)''')
                c.execute('''CREATE TABLE throttle (sasl_username text, client_address text, sender text, rcpt_max int, rcpt_count int, msg_max int, msg_count int, time_created bigint)''')
                c.execute('''CREATE TABLE blacklist_ip (cidr text, time_created bigint)''')
                c.execute('''CREATE TABLE whitelist_ip (cidr text, time_created bigint)''')
                c.execute('''CREATE_TABLE whitelist_sender (sender text)''')
                c.execute('''CREATE_TABLE blacklist_sender (sender text)''')
                conn.commit()
        except:
            exit
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind(('', port))
        self.listen(1)
    
    def cleanup(self):
        # flush the memory database to disk
        global conn
        # remove the old file
        if(os.path.exists(flush_database)):
            os.unlink(flush_database)
        flush_db=sqlite3.connect(flush_database)
        flush_query = "".join(line for line in conn.iterdump())
        flush_db.executescript(flush_query)

    def handle_accept(self):
        socket, address = self.accept()
        PolicyRequestHandler(socket)

class PolicyRequestHandler(asyncore.dispatcher_with_send):
    client_address = False
    sasl_username = False
    sender = False

    # this function checks the records against counters
    # a user is permitted to send a given amount of mail
    # message will be rejected if we have an overflow of the counter associated with the record
    def check_throttle(self):
        if throttle == False:
            return True
        global conn
        c = conn.cursor()
        try:
            if self.sasl_username.__len__() > 0:
                c.execute('''SELECT msg_count FROM throttle WHERE sasl_username= ?''',[self.sasl_username])
            else:
                c.execute('''SELECT msg_count FROM throttle WHERE sender = ?''',[self.sender])   
        except Exception:
            syslog.syslog("database problem")
            return True
   
    # this function checks the record for a distributed relay pattern
    # if the same sasl user or the same sender address tries to relay a mail
    # we check if the same username or sender address is used by multiple client addresses
    # if so, this is a certain sign of an abuse attempt
    def check_distributed_relay(self):
        if distributed_relay_detect == False:
            return True
        # check if we got multiple ips for the same sasl_username or sender
        global conn
        c = conn.cursor()
        try:
            if self.sasl_username.__len__() > 0:
                c.execute('''SELECT COUNT(DISTINCT(client_address)) FROM distributed_relay_detect WHERE sasl_username = ?''',[self.sasl_username])
            else:
                c.execute('''SELECT COUNT(DISTINCT(client_address)) FROM distributed_relay_detect WHERE sender = ?''',[self.sender]);
        except Exception, e:
            syslog.syslog("database problem")
            return True
    
        count_hosts=c.fetchone()[0]
        if count_hosts>distributed_relay_detect_max_hosts:
            return False
        else:
            # check if the record exists and create if not
            try:
                c.execute('''SELECT COUNT(client_address) FROM distributed_relay_detect WHERE sasl_username = ? AND sender = ? AND client_address = ?''',[self.sasl_username,self.sender,self.client_address])
            except Exception:
                syslog.syslog("check_distributed_relay: database problem")
                return True

            count=c.fetchone()[0]
            if(count==0):
                try:
                    # remove old record and insert the new triplet
                    c.execute('''DELETE FROM distributed_relay_detect WHERE time_created < ?''',[(int(time.time())-distributed_relay_detect_release_time)])
                    c.execute('''INSERT INTO distributed_relay_detect VALUES (?,?,?,?)''',[self.sasl_username,self.client_address,self.sender,int(time.time())])
                    syslog.syslog("new record (drt): client_address=%s sasl_username=%s sender=%s" % (self.client_address,self.sasl_username,self.sender))
                    conn.commit()
                except:
                    pass
        return True
 
    def check_record(self):
        global conn
        syslog.openlog("postfix-policy.py",syslog.LOG_INFO,syslog.LOG_MAIL)
        action = action_ok
        if self.client_address == False or self.sasl_username == False or self.sender == False:
            # if postfix sent incomplete data, this will never happen
            syslog.syslog("something missing in the record")
        
        if self.check_distributed_relay() == False:
            action = action_reject_distributed_detect
        
        # special case for bouncers overriding previous action, let postfix control this with other restrictions
        if self.sender.__len__() == 0:
            action = action_ok
	if action == action_ok:
	    syslog.syslog("client_address=%s sasl_username=%s from=%s action=ok" % (self.client_address,self.sasl_username,self.sender))
	elif action == action_reject_distributed_detect:
	    syslog.syslog("client_address=%s sasl_username=%s from=%s action=reject distributed relay" % (self.client_address,self.sasl_username,self.sender))
	syslog.closelog()
	return action

    def handle_read(self):
        thestring = self.recv(16384);
        lines = thestring.split("\n")
        for line in lines:
            line_array=line.split("=",1)
            if line_array[0] == 'client_address':
                self.client_address = line_array[1]
            elif line_array[0] == 'sasl_username':
                self.sasl_username=line_array[1]
            elif line_array[0] == 'sender':
                self.sender = line_array[1]
        action=self.check_record();
        self.send(action)
        self.close()
                
def shutdown_handler(signum, frame):
    global s
    s.cleanup()
    del s
    raise asyncore.ExitNow()

signal.signal(signal.SIGHUP, shutdown_handler)

s = PolicyServer(bind_ip, port)

try:
    asyncore.loop()
except:
    # graceful exit
    s.cleanup()
    del s
    raise asyncore.ExitNow()
