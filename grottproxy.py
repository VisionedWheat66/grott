#Grott Growatt monitor :  Proxy 
#       
# Updated: 2022-08-07
# Version 2.7.5

import socket
import select
import time
import sys
import struct
import textwrap
from itertools import cycle # to support "cycling" the iterator
import time, json, datetime, codecs
## to resolve errno 32: broken pipe issue (only linux)
if sys.platform != 'win32' :
   from signal import signal, SIGPIPE, SIG_DFL

from grottdata import procdata, decrypt, format_multi_line

#import mqtt                       
import paho.mqtt.publish as publish

#import libscrc for additional crc checking                        
# for compat reason (generate a message in the log) also done in proxy _init_
try:     
    import libscrc
except:
    print("\t **********************************************************************************")
    print("\t - Grott - libscrc not installed, no CRC checking only record validation on length!") 
    print("\t **********************************************************************************")


# Changing the buffer_size and delay, you can improve the speed and bandwidth.
# But when buffer get to high or delay go too down, you can broke things
buffer_size = 4096
#buffer_size = 65535
delay = 0.0002

def validate_record(xdata): 
    # validata data record on length and CRC (for "05" and "06" records)
    
    data = bytes.fromhex(xdata)
    ldata = len(data)
    len_orgpayload = int.from_bytes(data[4:6],"big")
    header = "".join("{:02x}".format(n) for n in data[0:8])
    protocol = header[6:8]

    if protocol in ("05","06"):
        lcrc = 4
        crc = int.from_bytes(data[ldata-2:ldata],"big")
    else: 
        lcrc = 0

    len_realpayload = (ldata*2 - 12 -lcrc) / 2

    if protocol != "02" :
                
        try: 
            crc_calc = libscrc.modbus(data[0:ldata-2])
        except: 
            #liscrc is not installed yet
            #print("\t - Grott - Validate datarecord - libscrc not installed, only validation on record length")  
            crc_calc = crc = 0 

    if len_realpayload == len_orgpayload :
        returncc = 0
        if protocol != "02" and crc != crc_calc:     
            returncc = 8    
    else : 
        returncc = 8

    return(returncc)


class Forward:
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self, host, port):
        try:
            self.forward.connect((host, port))
            return self.forward
        except Exception as e:
            print("\t - Grott - grottproxy forward error : ", e) 
            #print(e)
            return False  

class Proxy:
    input_list = []
    channel = {}

    def __init__(self, conf):
        print("\nGrott proxy mode started")

        # for compatibility reasons test if libscrc is installed and send error message
        # if not installed processing wil continue but records will only be validated on length and not on crc. 
        try:     
            import libscrc
        except:
            print("\t **********************************************************************************")
            print("\t - Grott - libscrc not installed, no CRC checking only record validation on length!") 
            print("\t **********************************************************************************")

        ## to resolve errno 32: broken pipe issue (Linux only)
        if sys.platform != 'win32':
            signal(SIGPIPE, SIG_DFL) 
        ## 
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #set default grottip address
        if conf.grottip == "default" : conf.grottip = '0.0.0.0'
        self.server.bind((conf.grottip, conf.grottport))
        #socket.gethostbyname(socket.gethostname())
        try: 
            hostname = (socket.gethostname())    
            print("Hostname :", hostname)
            print("IP : ", socket.gethostbyname(hostname), ", port : ", conf.grottport, "\n")
        except:  
            print("IP and port information not available") 

        self.server.listen(200)
        self.forward_to = [
            (conf.growattip, conf.growattport),
            (conf.growattip2, conf.growattport2)
        ]
        
    def main(self,conf):
        self.input_list.append(self.server)
        while 1:
            time.sleep(delay)
            ss = select.select
            inputready, outputready, exceptready = ss(self.input_list, [], [])
            for self.s in inputready:
                if self.s == self.server:
                    self.on_accept(conf)
                    break
                try: 
                    self.data, self.addr = self.s.recvfrom(buffer_size)
                except: 
                    if conf.verbose : print("\t - Grott connection error") 
                    self.on_close(conf)   
                    break
                if len(self.data) == 0:
                    self.on_close(conf)
                    break
                else:
                    self.on_recv(conf)

    def get_active_socket_or_tuple(self):
        possible_socket = None
        for key in self.channel.keys():
            if isinstance(key, tuple) and self.s in key:
                possible_socket = self.channel[key] # returning a socket
                break
        if not possible_socket:
            possible_socket = self.channel[self.s] # returning a tuple or a socket not in a tuple

        return possible_socket

    def get_tuple_for_socket(self, socket):
        for key in self.channel.keys():
            if isinstance(key, tuple) and socket in key:
                return key
        return socket

    def on_accept(self,conf):
        forward1 = Forward().start(self.forward_to[0][0], self.forward_to[0][1])
        forward2 = Forward().start(self.forward_to[1][0], self.forward_to[1][1])

        clientsock, clientaddr = self.server.accept()
        if conf.verbose: print("\t -", clientaddr, "has connected")

        if forward1 and forward2:
            forwardsTuple = (forward1, forward2)
        elif forward1:
            forwardsTuple = (forward1,)
        else:
            forwardsTuple = None

        if forwardsTuple:
            self.input_list.append(clientsock)
            for forward in forwardsTuple:
                self.input_list.append(forward)
            self.channel[clientsock] = forwardsTuple
            self.channel[forwardsTuple] = clientsock
        else:
            if conf.verbose: 
                print("\t - Can't establish connection with remote server."),
                print("\t - Closing connection with client side", clientaddr)
            clientsock.close()

    def on_close(self,conf):
        if conf.verbose: 
            #try / except to resolve errno 107: Transport endpoint is not connected 
            try: 
                print("\t -", self.s.getpeername(), "has disconnected")
            except:  
                print("\t -", "peer has disconnected")

        #remove objects from input_list
        tuple_or_socket = self.get_tuple_for_socket(self.s)
        if isinstance(tuple_or_socket, tuple):
            for forward in tuple_or_socket:
                self.input_list.remove(forward)
        else:
            self.input_list.remove(tuple_or_socket)

        possible_socket = self.get_active_socket_or_tuple()
        if isinstance(possible_socket, tuple):
            for forward in possible_socket:
                self.input_list.remove(forward)
        else:
            self.input_list.remove(possible_socket)
        # close the connection with client
        if isinstance(self.channel[possible_socket], tuple):
            for forward in self.channel[possible_socket]:
                forward.close()  # equivalent to do self.s.close()
        else:
            self.channel[possible_socket].close()
        # close the connection with remote server
        if isinstance(possible_socket, tuple):
            for forward in possible_socket:
                forward.close()
        else:
            possible_socket.close()
        # delete both objects from channel dict
        del self.channel[possible_socket]
        del self.channel[self.get_tuple_for_socket(self.s)]

    def on_recv(self,conf):
        data = self.data      
        possible_socket = self.get_active_socket_or_tuple()
        print("")
        print("\t - " + "Growatt packet received:")
        print("\t\t ", possible_socket)
        
        #test if record is not corrupted
        vdata = "".join("{:02x}".format(n) for n in data)
        validatecc = validate_record(vdata)
        if validatecc != 0 : 
            print(f"\t - Grott - grottproxy - Invalid data record received, processing stopped for this record")
            #Create response if needed? 
            #self.send_queuereg[qname].put(response)
            return  

        # FILTER!!!!!!!! Detect if configure data is sent!
        header = "".join("{:02x}".format(n) for n in data[0:8])
        if conf.blockcmd : 
            #standard everything is blocked!
            print("\t - " + "Growatt command block checking started") 
            blockflag = True 
            #partly block configure Shine commands                   
            if header[14:16] == "18" :         
                if conf.blockcmd : 
                    if header[6:8] == "05" or header[6:8] == "06" : confdata = decrypt(data) 
                    else :  confdata = data

                    #get conf command (location depends on record type), maybe later more flexibility is needed
                    if header[6:8] == "06" : confcmd = confdata[76:80]
                    else: confcmd = confdata[36:40]
                    
                    if header[14:16] == "18" : 
                        #do not block if configure time command of configure IP (if noipf flag set)
                        if conf.verbose : print("\t - Grott: Shine Configure command detected")                                                    
                        if confcmd == "001f" or (confcmd == "0011" and conf.noipf) : 
                            blockflag = False
                            if confcmd == "001f": confcmd = "Time"
                            if confcmd == "0011": confcmd = "Change IP"
                            if conf.verbose : print("\t - Grott: Configure command not blocked : ", confcmd)    
                    else : 
                        #All configure inverter commands will be blocked
                        if conf.verbose : print("\t - Grott: Inverter Configure command detected")
            
            #allow records: 
            if header[12:16] in conf.recwl : blockflag = False     

            if blockflag : 
                print("\t - Grott: Record blocked: ", header[12:16])
                if header[6:8] == "05" or header[6:8] == "06" : blockeddata = decrypt(data) 
                else :  blockeddata = data
                print(format_multi_line("\t\t ",blockeddata))
                return

        # send data to destination
        if isinstance(possible_socket, tuple):
            for forward in possible_socket:
                forward.send(data)
        else:
            possible_socket.send(data)
        if len(data) > conf.minrecl :
            #process received data
            procdata(conf,data)    
        else:     
            if conf.verbose: print("\t - " + 'Data less then minimum record length, data not processed') 
                
