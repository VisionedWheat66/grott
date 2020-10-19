# grottdata.py processing data  functions
# Updated: 2020-10-03
# Version 2.2.1d

import time
import sys
import struct
import textwrap
from itertools import cycle # to support "cycling" the iterator
import json, datetime, codecs 
# requests

#import mqtt                       
import paho.mqtt.publish as publish

# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

#decrypt data. 
def decrypt(decdata) :   

    ndecdata = len(decdata)

    # Create mask and convert to hexadecimal
    mask = "Growatt"
    hex_mask = ['{:02x}'.format(ord(x)) for x in mask]    
    nmask = len(hex_mask)

    #start decrypt routine 
    unscrambled = list(decdata[0:8])                                            #take unscramble header
    
    for i,j in zip(range(0,ndecdata-8),cycle(range(0,nmask))): 
        unscrambled = unscrambled + [decdata[i+8] ^ int(hex_mask[j],16)]
    
    result_string = "".join("{:02x}".format(n) for n in unscrambled)
    
    print("\t - " + "Growatt data decrypted V2")   
    return result_string        

def procdata(conf,data):    
    if conf.verbose: 
        print("\t - " + "Growatt original Data:") 
        print(format_multi_line("\t\t ", data))

    header = "".join("{:02x}".format(n) for n in data[0:8])
    ndata = len(data)
    
    # automatic detect protocol (decryption and protocol) only if compat = False!
    novalidrec = False
    if conf.compat is False : 
        if conf.verbose : 
            print("\t - " + "Grott automatic protocol detection")  
            print("\t - " + "Grott data record length", ndata)
        #print(header)
        layout = "T" + header[6:8] + header[12:14] + header[14:16]
        if ndata > 375:  layout = layout + "X"

        try:
            if conf.verbose : print("\t - " + "layout   : ", layout)
            conf.decrypt =  conf.recorddict[layout]["decrypt"]
            if conf.verbose : print("\t - " + "decrypt  : ",conf.decrypt)
            #print("\t - " + "offset   : ", conf.offset)
        except: 
            #if conf.verbose : print("\t - " + "Grott data record not defined") 
            #set novalidrec flag so print encryption is done but data processing not
            novalidrec = True   
            #return 

    
    if conf.decrypt: 

        result_string = decrypt(data)    
        # #ndata = len(data)

        # # Create mask and convert to hexadecimal
        # mask = "Growatt"
        # hex_mask = ['{:02x}'.format(ord(x)) for x in mask]    
        # nmask = len(hex_mask)

        # #start decrypt routine 
        # unscrambled = list(data[0:8])                                            #take unscramble header

        # for i,j in zip(range(0,ndata-8),cycle(range(0,nmask))): 
        #     unscrambled = unscrambled + [data[i+8] ^ int(hex_mask[j],16)]
       
        # result_string = "".join("{:02x}".format(n) for n in unscrambled)
        
        # if conf.verbose: print("\t - " + "Growatt data decrypted")           

    else: 
        #do not decrypt 
        result_string = data.hex()
        if conf.verbose: print("\t - " + "Growatt unencrypted data used")                                      
                                                        
    if conf.verbose: 
        print("\t - " + 'Growatt plain data:')
        print(format_multi_line("\t\t ", result_string)) 

    # test position : 
    # print(result_string.find('0074' ))

    # Test length if < 12 it is a data ack record, if novalidrec flag is true it is not a (recognized) data record  
    if ndata < 12 or novalidrec == True: 
        if conf.verbose : print("\t - " + "Grott data ack record or data record not defined no processing done") 
        return

    # Inital flag to detect off real data is processed     
    dataprocessed = False

    if conf.compat is False: 
        # new method if compat = False (autoatic detection):  
       
        if conf.verbose: 
           print("\t - " + 'Growatt new layout processing')
           print("\t\t - " + "decrypt       : ",conf.decrypt)
           print("\t\t - " + "offset        : ", conf.offset)
           print("\t\t - " + "record layout : ", layout)
           print() 
           
        pvserial = result_string[conf.recorddict[layout]["pvserial"]:conf.recorddict[layout]["pvserial"]+20]
        pvstatus = int(result_string[conf.recorddict[layout]["pvstatus"]:conf.recorddict[layout]["pvstatus"]+4],16)
        pvpowerin = int(result_string[conf.recorddict[layout]["pvpowerin"]:conf.recorddict[layout]["pvpowerin"]+8],16)
        pv1voltage = int(result_string[conf.recorddict[layout]["pv1voltage"]:conf.recorddict[layout]["pv1voltage"]+4],16)
        pv1current = int(result_string[conf.recorddict[layout]["pv1current"]:conf.recorddict[layout]["pv1current"]+4],16)
        pv1watt    = int(result_string[conf.recorddict[layout]["pv1watt"]:conf.recorddict[layout]["pv1watt"]+8],16)
        pv2voltage = int(result_string[conf.recorddict[layout]["pv2voltage"]:conf.recorddict[layout]["pv2voltage"]+4],16)
        pv2current = int(result_string[conf.recorddict[layout]["pv2current"]:conf.recorddict[layout]["pv2current"]+4],16)
        pv2watt    = int(result_string[conf.recorddict[layout]["pv2watt"]:conf.recorddict[layout]["pv2watt"]+8],16)
        pvpowerout = int(result_string[conf.recorddict[layout]["pvpowerout"]:conf.recorddict[layout]["pvpowerout"]+8],16)
        pvfrequentie = int(result_string[conf.recorddict[layout]["pvfrequentie"]:conf.recorddict[layout]["pvfrequentie"]+4],16)
        pvgridvoltage = int(result_string[conf.recorddict[layout]["pvgridvoltage"]:conf.recorddict[layout]["pvgridvoltage"]+4],16)
        pvenergytoday= int(result_string[conf.recorddict[layout]["pvenergytoday"]:conf.recorddict[layout]["pvenergytoday"]+8],16)
        pvenergytotal= int(result_string[conf.recorddict[layout]["pvenergytotal"]:conf.recorddict[layout]["pvenergytotal"]+8],16)
        pvtemperature = int(result_string[conf.recorddict[layout]["pvtemperature"]:conf.recorddict[layout]["pvtemperature"]+4],16)
        pvipmtemperature = int(result_string[conf.recorddict[layout]["pvipmtemperature"]:conf.recorddict[layout]["pvipmtemperature"]+4],16)
        if conf.recorddict[layout]["date"] > 0:
            if conf.verbose: print("\t - " + 'Grott data record date/time processing started')
            #date
            pvyearI =  int(result_string[conf.recorddict[layout]["date"]:conf.recorddict[layout]["date"]+2],16)
            if pvyearI < 10 : pvyear = "200" + str(pvyearI)
            else: pvyear = "20" + str(pvyearI) 
            pvmonthI = int(result_string[conf.recorddict[layout]["date"]+2:conf.recorddict[layout]["date"]+4],16)
            if pvmonthI < 10 : pvmonth = "0" + str(pvmonthI)
            else: pvmonth = str(pvmonthI) 
            pvdayI = int(result_string[conf.recorddict[layout]["date"]+4:conf.recorddict[layout]["date"]+6],16)
            if pvdayI < 10 : pvday = "0" + str(pvdayI)
            else: pvday = str(pvdayI) 
            #Time
            pvhourI = int(result_string[conf.recorddict[layout]["date"]+6:conf.recorddict[layout]["date"]+8],16)
            if pvhourI < 10 : pvhour = "0" + str(pvhourI)
            else: pvhour = str(pvhourI) 
            pvminuteI = int(result_string[conf.recorddict[layout]["date"]+8:conf.recorddict[layout]["date"]+10],16)
            if pvminuteI < 10 : pvminute = "0" + str(pvminuteI)
            else: pvminute = str(pvminuteI) 
            pvsecondI = int(result_string[conf.recorddict[layout]["date"]+10:conf.recorddict[layout]["date"]+12],16)
            if pvsecondI < 10 : pvsecond = "0" + str(pvsecondI)
            else: pvsecond = str(pvsecondI) 
            
            if (pvyearI > 19 and pvyearI  < 75) :
                #test if the year is reasonable value otherwise date is not part of the growatt data (normally it is 0 then)
                pvdate = pvyear + "-" + pvmonth + "-" + pvday + "T" + pvhour + ":" + pvminute + ":" + pvsecond
                if conf.verbose : print("\t - ", pvdate)            
            else: 
                if conf.verbose : print("\t - " + "No or no valid date found")            

        dataprocessed = True


    else:
        serialfound = False 
        if(result_string.find(conf.SN) > -1):
            serialfound = True   

        if serialfound == True:
            #Change in trace in future
                
            if conf.verbose: print("\t - " + 'Growatt processing values for: ', bytearray.fromhex(conf.SN).decode())
            
            #Retrieve values 
            snstart = result_string.find(conf.SN)  
            pvserial = result_string[snstart:snstart+20]
            pvstatus = int(result_string[snstart+conf.offset*2+15*2:snstart+conf.offset*2+15*2+4],16)
            #Only process value if pvstatus is oke (this is because unexpected pvstatus of 257)
            if pvstatus == 0 or pvstatus == 1:
                pvpowerin = int(result_string[snstart+conf.offset*2+17*2:snstart+conf.offset*2+17*2+8],16)
                pv1voltage = int(result_string[snstart+conf.offset*2+21*2:snstart+conf.offset*2+21*2+4],16)
                pv1current = int(result_string[snstart+conf.offset*2+23*2:snstart+conf.offset*2+23*2+4],16)
                pv1watt    = int(result_string[snstart+conf.offset*2+25*2:snstart+conf.offset*2+25*2+8],16)
                pv2voltage = int(result_string[snstart+conf.offset*2+29*2:snstart+conf.offset*2+29*2+4],16)
                pv2current = int(result_string[snstart+conf.offset*2+31*2:snstart+conf.offset*2+31*2+4],16)
                pv2watt    = int(result_string[snstart+conf.offset*2+33*2:snstart+conf.offset*2+33*2+8],16)
                pvpowerout = int(result_string[snstart+conf.offset*2+37*2:snstart+conf.offset*2+37*2+8],16)
                pvfrequentie = int(result_string[snstart+conf.offset*2+41*2:snstart+conf.offset*2+41*2+4],16)
                pvgridvoltage = int(result_string[snstart+conf.offset*2+43*2:snstart+conf.offset*2+43*2+4],16)
                pvenergytoday= int(result_string[snstart+conf.offset*2+67*2:snstart+conf.offset*2+67*2+8],16)
                pvenergytotal= int(result_string[snstart+conf.offset*2+71*2:snstart+conf.offset*2+71*2+8],16)
                pvtemperature = int(result_string[snstart+conf.offset*2+79*2:snstart+conf.offset*2+79*2+4],16)
                pvipmtemperature = int(result_string[snstart+conf.offset*2+97*2:snstart+conf.offset*2+97*2+4],16)
                dataprocessed = True
                
            else:
                if conf.verbose: print("\t - " + 'No valid monitor data, PV status: :', pvstatus)                            
            
        else:   
            if conf.verbose: print("\t - "+ 'No Growatt data processed or SN not found:')
            if conf.trace: 
                print("\t - "+ 'Growatt unprocessed Data:')
                print(format_multi_line("\t\t - ", result_string))

    if dataprocessed: 
        # only sendout data to MQTT if it is processed. 
        pvserial = codecs.decode(pvserial, "hex").decode('utf-8')
        if conf.verbose:
            print("\t- " + "Grott values retrieved:")
            print("\t\t - " + "pvserial:         ", pvserial)
            print("\t\t - " + "pvstatus:         ", pvstatus) 
            print("\t\t - " + "pvpowerin:        ", pvpowerin/10)
            print("\t\t - " + "pvpowerout:       ", pvpowerout/10)
            print("\t\t - " + "pvenergytoday:    ", pvenergytoday/10)
            print("\t\t - " + "pvenergytotal:    ", pvenergytotal/10)
            print("\t\t - " + "pv1watt:          ", pv1watt/10)
            print("\t\t - " + "pv2watt:          ", pv2watt/10)
            print("\t\t - " + "pvfrequentie:     ", pvfrequentie/100)
            print("\t\t - " + "pvgridvoltage:    ", pvgridvoltage/10)
            print("\t\t - " + "pv1voltage:       ", pv1voltage/10)
            print("\t\t - " + "pv1current:       ", pv1current/10)
            print("\t\t - " + "pv2voltage:       ", pv2voltage/10)
            print("\t\t - " + "pv2current:       ", pv2current/10)
            print("\t\t - " + "pvtemperature:    ", pvtemperature/10)
            print("\t\t - " + "pvipmtemperature: ", pvipmtemperature/10)

        #test which date to be used.     
        try: 
            jsondate = pvdate 
        except: 
            jsondate =datetime.datetime.now().replace(microsecond=0).isoformat()

        buffered = "no"
        if header[14:16] == "50" : buffered = "yes"

        #create JSON message                    
        jsonmsg = json.dumps({"device":pvserial,"time":jsondate,"buffered":buffered,
            "values":{
                        "pvstatus":pvstatus,
                        "pv1watt":pv1watt,
                        "pv2watt":pv2watt,
                        "pvpowerin":pvpowerin,
                        "pvpowerout":pvpowerout,
                        "pvfrequentie":pvfrequentie,
                        "pvgridvoltage":pvgridvoltage,                             
                        "pvenergytoday":pvenergytoday,
                        "pvenergytotal":pvenergytotal,
                        "pv1voltage":pv1voltage,
                        "pv2voltage":pv2voltage,
                        "pv1current":pv1current,
                        "pv2current":pv2current,
                        "pvtemperature":pvtemperature,
                        "pvipmtemperature":pvipmtemperature}                                
                        })
        if conf.verbose:
            print("\t - " + "MQTT jsonmsg: ")        
            #print("\t\t - " + jsonmsg)     
            print(format_multi_line("\t\t\t ", jsonmsg))   
            
        if conf.nomqtt != True:
            try: 
                publish.single(conf.mqtttopic, payload=jsonmsg, qos=0, retain=False, hostname=conf.mqttip,port=conf.mqttport, client_id=conf.inverterid, keepalive=60, auth=conf.pubauth)
                if conf.verbose: print("\t - " + 'MQTT message message sent') 
            except TimeoutError:     
                if conf.verbose: print("\t - " + 'MQTT connection time out error') 
            except ConnectionRefusedError:     
                if conf.verbose: print("\t - " + 'MQTT connection refused by target')     
            except BaseException as error:     
                if conf.verbose: print("\t - "+ 'MQTT send failed:', str(error)) 
        else:
            if conf.verbose: print("\t - " + 'No MQTT message sent, MQTT disabled') 

        # process pvoutput if enabled
        if conf.pvoutput == True or conf.pvoutput == "True" :      
            import requests
            if conf.verbose : print("\t - " + "Grott send data to PVOutput : ") 
            pvheader = { 
                "X-Pvoutput-Apikey"     : conf.pvapikey,
                "X-Pvoutput-SystemId"   : conf.pvsystemid
            }
            
            pvodate = jsondate[:4] +jsondate[5:7] + jsondate[8:10]
            pvotime = jsondate[11:16] 
                            
            pvdata = { 
                "d"     : pvodate,
                "t"     : pvotime,
                "v1"    : pvenergytoday*100,
                "v2"    : pvpowerout/10,
                "v6"    : pvgridvoltage/10
                }
            #print(pvheader)
            if conf.verbose : print("\t\t - ", pvdata)
            reqret = requests.post(conf.pvurl, data = pvdata, headers = pvheader)
            if conf.verbose :  print("\t - " + "Grott PVOutput response: ") 
            if conf.verbose : print("\t\t - ", reqret.text)
        else: 
            if conf.verbose : print("\t - " + "Grott Send data to PVOutput disabled ") 
            