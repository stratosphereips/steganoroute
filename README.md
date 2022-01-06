# Steganoroute

A tool to send steganographed text messages to mtr using fake hops in the network.


## Author

Sebastian garcia, eldraco@gmail.com

## Description

Steganoroute is a tool to send steganographed text messages to another computer over the network. The receiver must make a traceroute to the sender using the mtr program (and pressing d once to switch the display mode to the continuous graph). This tool, the sender, creates several fake hops and makes them answer the ICMP packets (or not) to write the letters one by one on the mtr client screen.

So far, you can only use mtr in one computer. Sorry, I'm working on this.

## Features
- It can print upper and lower-case letters.
- It can print in normal or color-inverse mode.
- It can loop forever.
- It should work on your own localhost computer, on your LAN and over the Internet.
- It uses the Sinclair ZX Spectrum (1982) font.
- You can select the TTL value on demand and therefore 'move' the text up and down the mtr graph.
- You can filter the IP address that should receive the traceroute. If you don't filter it, every traceroute coming out of the server will mysteriously add fake hops to any destination! Oh my... what did I create?
- You can feel the sensation of being MITMed by the top intelligence organizations in the world by using the conspiracy mode!
- It can automatically manage your firewall to stop receiving pings during operation.


## The fake hop trick

How does the fake hop trick in traceroute work?
Well, I'm not sure if anybody else has done this previously, so I'm gonna write how I did it.

In few words: I send a forged ICMP 'TTL expired in transit' packet with a spoofed source IP address of my choice. 

The large explanation:
Traceroute programs send ICMP echo-request packets with increasing TTL values. Each hop must answer, when the TTL value reaches zero, an 'ICMP TTL expired in transit' packet.
Steganoroute answers each ICMP packet, with a certain TTL value, from a different forged source IP address. So, for example, for the TTL values 2,3,4,5,6 , different IP addresses are used to send the 'TTL expired' packet.
In this way, you can create any number of fake hops before of after your real host.

## Firewall
Your computer should not answer pings in order for this program to work. So, if you are answering pings (or you don't know and you never touched your firewall)  then you have two options: do it yourself or let the program do it.

- Easy way: Use -f parameter and let the program do it.
- Paranoid way: Use something like `iptables -D INPUT 1 -p icmp --icmp-type 8 -j DROP` to stop the pings
- To delete that rule afterwards use `iptables -D INPUT 1`



Usage
=====
Remember that your computer should NOT answer to ping during operation, so you can stop it yourself by hand, or use -f to let the program manage that for you.

### To test on your own computer and loop forever

Server:

```
./steganoroute.py -i lo -m "Hello World" -l -f
```

Only the first client that connects receives the text right. Any further client only destroys every text on all the clients.

Client:
```
mtr -t <your LAN IP, not localhost> (and press d after the start)
```

### To use on any other network and loop forever

Server:
```
./steganoroute.py -i <your-lan-interface> -m "Hello World" -l -f
```
Only the first client that connects receives the text right. Any further client only destroys every text on all the clients.

If your interface is wlan0, then:
```
./steganoroute.py -i wlan0 -m "Hello World" -l -f
```

Client:
```
mtr -t <server-ip> (and press d after the start)
```
For example if your server is 192.168.1.2, then (and press d after the start):
```
mtr -t 192.168.1.2
```

To change the TTL value on demand
---------------------------------
A TTL of 1 is useful in the local network.
```
./steganoroute.py -i wlan0 -m "Hello World" -l -t 1 -f
```

If you keep the mtr client up, and you stop the server, change the TTL value and start it again, you will see how you can 'move' the text down and up the mtr!
```
./steganoroute.py -i wlan0 -m "Hello World" -l -t 2 -f
./steganoroute.py -i wlan0 -m "Hello World" -l -t 3 -f
./steganoroute.py -i wlan0 -m "Hello World" -l -t 4 -f
```

This should be done after the mtr has begin printing the text with the TTL value that reaches your computer. If you start with a TTL value of 10 and the mtr client is only 1 hop away, it will see nothing.


### To filter which client is authorized to connect

```
./steganoroute.py -i wlan0 -m "Hello World" -l -t 1 -s 192.168.0.20 -f
```

Only IP address 192.168.0.20 is authorized to receive the message. So no one can mess with your text.



## About the font

Now it is using the Sinclair ZX Spectrum (1982) font. It is a regular sans font.


## Why root?

This program needs root permissions to sniff packets in the network.


## TODO
- Implement chat mode. You can type new messages live.
- Implement new characters in the font as well as numbers.
- Move the font to a separate file, to allow multiple fonts.
- Implement other fonts.
- Make it work with multiple mtr clients. (public mode) This seems not to be possible. I've implemented threads and it still have to much lag.
