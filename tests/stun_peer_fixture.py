#!/usr/bin/env python3
"""Native STUN peer fixture, only inside an empty private network namespace."""
import json, socket, struct, subprocess, sys, threading, time
for address in ['192.0.2.2','74.125.250.129']:
    subprocess.run(['ip','addr','add',address+'/32','dev','lo'],check=True)
subprocess.run(['ip','link','set','lo','up'],check=True)
subprocess.run(['ip','route','replace','local','74.125.250.129/32','dev','lo','table','local','src','192.0.2.2'],check=True)
exe=sys.argv[1]
cookie=bytes.fromhex('2112a442')
for index,mode in enumerate(['valid','invalid','wrong_ip','wrong_port','oversize','timeout']):
    server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); server.bind(('74.125.250.129',19302)); server.settimeout(5)
    errors=[]
    def peer():
        try:
            request,source=server.recvfrom(1024)
            assert len(request)==20 and request[:8]==b'\x00\x01\x00\x00'+cookie and source==('192.0.2.2',12600+index)
            tx=request[8:]
            mapped='192.0.2.1' if mode=='wrong_ip' else source[0]
            port=source[1]+(mode=='wrong_port')
            payload=struct.pack('!HHBBH',0x20,8,0,1,port^0x2112)+bytes(a^b for a,b in zip(socket.inet_aton(mapped),cookie))
            response=b'\x01\x01'+struct.pack('!H',len(payload))+cookie+tx+payload
            if mode=='valid':
                spoof=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); spoof.bind(('74.125.250.129',19303))
                spoof.sendto(response,source); spoof.close()
                server.sendto(response[:8]+bytes(x^1 for x in tx)+payload,source)
            if mode=='invalid': response=response[:4]+b'BAD!'+response[8:]
            if mode=='oversize': response+=b'0'*4096
            if mode=='timeout':
                until=time.monotonic()+4.2
                while time.monotonic()<until:
                    try: server.sendto(response[:8]+bytes(x^1 for x in tx)+payload,source)
                    except ConnectionRefusedError: pass
                    time.sleep(.01)
            else: server.sendto(response,source)
        except BaseException as e: errors.append(e)
    thread=threading.Thread(target=peer); thread.start()
    start=time.monotonic(); p=subprocess.run([exe,str(12600+index)],capture_output=True,text=True,timeout=6); elapsed=time.monotonic()-start
    thread.join(timeout=6); server.close(); assert not thread.is_alive() and not errors,errors
    m=json.loads(p.stdout)
    assert m['local_ip']=='192.0.2.2' and m['local_port']==12600+index and m['remote_ip']=='74.125.250.129' and m['remote_port']==19302,m
    if mode=='valid': assert p.returncode==0 and m['binding_success'] and m['route_verified'] and m['ignored_transactions']==1,m
    else:
        assert p.returncode==1 and not m['route_verified'],m
        assert m['failure']==dict(invalid='invalid_stun',wrong_ip='route',wrong_port='route',oversize='oversize',timeout='timeout')[mode],m
    if mode=='timeout': assert 3.7<elapsed<5 and not m['binding_success'] and m['ignored_transactions']>100,(elapsed,m)
print('PASS REAL native fixed-socket STUN IO, connected peer filtering, unrelated fake TxIDs, malformed/oversized replies, mapped tuple rejection, 4s non-extending deadline (private netns only)')
