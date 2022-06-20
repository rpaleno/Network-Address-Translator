import threading
import random
from scapy.packet import Packet, Raw
from scapy.sendrecv import send, sniff
from scapy.layers.inet import TCP, IP, Ether, ICMP

PRIVATE_IFACE = "eth0" 
PRIVATE_IP = "10.0.0.2"

PUBLIC_IFACE = "eth1" 
PUBLIC_IP = "172.16.20.2"

NAT_TABLE_PRIV = {} 
NAT_TABLE_PUB = {} 
USED_PORTS = [1023]

def generate_unique_port():
  port = random.randrange(1024,65535) 
  for i in USED_PORTS:
    if(port == i):
      port = random.randrange(1024,65535)
      return generate_unique_port() 
    else:
      return port

def process_pkt_private(pkt: Packet): 
  if pkt.sniffed_on == PRIVATE_IFACE:
    # print("received private pkt", pkt.sniffed_on, pkt.summary())
    if ICMP in pkt:
      # if packet is an ICMP request 
      if(pkt[ICMP].type == 8):
        
        # map public address and ID to private address
        NAT_TABLE_PUB[PUBLIC_IP + "," + str(pkt[ICMP].id)] = pkt[IP].src 
        
        # Create a new IP packet with specified src and dst
        new_pkt = IP(src=PUBLIC_IP, dst=pkt[IP].dst) / pkt[ICMP] 
        
        # Send the new packet over the public interface
        send(new_pkt, iface=PUBLIC_IFACE, verbose=False)
        
    elif TCP in pkt: 
      if(pkt[TCP].flags == "S"):
        public_port = generate_unique_port()
        print(public_port)
        
        #map public address and public port to private address and private port
        NAT_TABLE_PRIV[str(pkt[IP].src) + "," + str(pkt[TCP].sport)] = PUBLIC_IP + "," + str(public_port)
        NAT_TABLE_PUB[PUBLIC_IP + "," + str(public_port)] = str(pkt[IP].src) + "," + str(pkt[TCP].sport)
        #update source port value
        #pkt[TCP].sport = public_port
        pkt.show() 
      
      if(pkt[TCP].dport == 80):
        print("ok")
        info = NAT_TABLE_PRIV[str(pkt[IP].src) + "," + str(pkt[TCP].sport)]

        # parse info into IP and port
        info = info.split(',') 
        dest = info[0].strip() 
        port = info[1].strip()

        if Raw in pkt: 
          load1 = pkt[Raw].load
          
        else:
          load1 = ""
          
        # Create a new IP packet with specified src and dst
        new_pkt = IP(src=PUBLIC_IP, dst=pkt[IP].dst) / TCP(sport=int(port), dport=pkt[TCP].dport,seq=pkt[TCP].seq,ack=pkt[TCP].ack,flags=pkt[TCP].flags,window=pkt[TCP].window,options=pkt[TCP].options,urgptr=pkt[TCP].urgptr) / Raw(load=load1)

        # Send the new packet over the public interface
        send(new_pkt, iface=PUBLIC_IFACE, verbose=False)
        
        
        
def process_pkt_public(pkt: Packet): if pkt.sniffed_on == PUBLIC_IFACE:
  #print("received public pkt", pkt.sniffed_on, pkt.summary())
  if ICMP in pkt:
    # if packet is a reply 
    if(pkt[ICMP].type == 0):
      # lookup private address mapped to public address
      dest = NAT_TABLE_PUB[PUBLIC_IP + "," + str(pkt[ICMP].id)] 
      
      # Create a new IP packet with specified src and dst
      new_pkt = IP(src=pkt[IP].src, dst=dest) / pkt[ICMP] 
      
      # Send the new packet over the private interface
      send(new_pkt, iface=PRIVATE_IFACE, verbose=False)
      
  elif TCP in pkt:
    if(pkt[TCP].sport == 80 or pkt[TCP].dport == 80):
      print("received public pkt", pkt.sniffed_on, pkt.summary()) 
      pkt.show()
      
      if(pkt[TCP].sport == 80):
        
        # lookup private address mapped to public address
        info = NAT_TABLE_PUB[PUBLIC_IP + "," + str(pkt[TCP].dport)]
        
        # parse info into IP and port
        info = info.split(',') 
        dest = info[0].strip()
        port = info[1].strip()
        
        if Raw in pkt: 
          load2=pkt[Raw].load
        
        else:
          load2 = ""
            
        new_pkt = IP(src=pkt[IP].src, dst=dest) / TCP(sport=pkt[TCP].sport, dport=int(port),seq=pkt[TCP].seq,ack=pkt[TCP].ack,flags=pkt[TCP].flags,window=pkt[TCP] .window,options=pkt[TCP].options,urgptr=pkt[TCP].urgptr) / Raw(load=load2)
        print("new public pkt", new_pkt.sniffed_on, new_pkt.summary()) pkt.show()
        send(new_pkt, iface=PRIVATE_IFACE, verbose=False)

def private_listener():
  print("sniffing packets on the private interface") 
  sniff(prn=process_pkt_private, iface=PRIVATE_IFACE, filter="icmp or tcp")

def public_listener():
  print("sniffing packets on the public interface") 
  sniff(prn=process_pkt_public, iface=PUBLIC_IFACE, filter="icmp or tcp")

def main():
  thread1 = threading.Thread(target=private_listener) thread2 = threading.Thread(target=public_listener) thread1.start()
  thread2.start()
  thread1.join()
  thread2.join()

main()
