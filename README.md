# QuicVPN
QuicVPN, a replacement of OpenVPN, in rust, based on Quic

I've been using OpenVpn in my work, and loved it. after I started to learn rust, I wondering, why not replace the openvpn? to me, it's always unnecessarily complicated. Hence this project.

The code seems very short, but I have been working on it of and off for over a month, mainly because I was not not familiar with Rust, trying to figure out every corner of it, especially the async trait and life time problem.

Another thing I want to get familiar with is Quic. It's been out for a while, I really feel it makes a lot sense to use Quic as a VPN tunnel. It's encrypted, it's fast, it's the future, and it's already there. Somebody has already done the heavy lifting for you! Thanks to the quinn team.

Along the way, I realize, why not add a proxy server for fun! So it became a Vpn server and Proxy Server at the same time

#Installation
I am trying to make the use of this product as painless as possible, because that's the bad experience I had with OpenVpn. But while working on it. I realize all the decisions OpenVpn made makes sense. :-) Network is complicated!

So, we will go though only one scenario. If your scenario is different, then you will have to get familiar with all the networking yourself.

Let's say you have a server group on the cloud, with a network segment of: 192.168.120.0/24. And you are sitting in your office, with a network segment of: 192.168.0.0/24. And you want to access all the servers freely from your office computer.

Then you want to run the Quic_Server on one of your servers, listen to the local IP, and run the QuicClient on your office computer.
Now here is the catch, it won't work immediately, you need to setup route on the client side, and snat on the server side.

details coming later. But the executable itself has enough help message. All you need to do is run: quic_server, it will tell you what to do. I really hope you can get it up and running with reading the manual.

The typical scenario is: Server on a ubuntu machine, client on a ubuntu or a windows machine. As to MacOS, never tested on it.


