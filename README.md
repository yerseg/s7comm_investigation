# s7comm_investigation
This is a team project on the subject of information security of cyber industrial systems. Made by students of MEPhI group B17-505.

For installation:
- `pip install snap7`
- download snap7.dll from snap7 opensource lib and copy it to directory with python files

## How to build Suricata for S7 protocol on Linux
#### You can see [my fork](https://github.com/yerseg/suricata) of [Suricata](https://github.com/OISF/suricata) repo 

Firstly, download packages and configure project, then build suricata
1. `cd ~`
1. `sudo apt-get update && sudo apt-get upgrade -y`
1. `sudo apt-get install libpcre3 libpcre3-dbg libpcre3-dev build-essential libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev pkg-config zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 make libmagic-dev libjansson-dev libnss3-dev libgeoip-dev liblua5.1-dev libhiredis-dev libevent-dev liblz4-dev m4 autoconf autogen cargo python3-pip cbindgen`
1. `sudo pip install python-snap7`
1. `git clone https://github.com/yerseg/suricata.git`
1. `cd suricata/`
1. `git clone https://github.com/OISF/libhtp.git`
1. `sudo ./autogen.sh`
1. `sudo ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var`
1. `sudo mkdir /var/log/suricata`
1. `sudo mkdir /etc/suricata`
1. `sudo cp classification.config /etc/suricata`
1. `sudo cp reference.config /etc/suricata`
1. `sudo cp suricata.yaml /etc/suricata`
1. `sudo make && sudo make install-full`

Install testing stend for S7
1. `cd ~`
1. `git clone https://github.com/yerseg/s7comm_investigation.git`
1. `cd s7comm_investigation/`
1. `sudo cp ./libsnap7.so /usr/lib`
1. `sudo ldconfig`
1. Now you can run server and client by python3. Don't forget use sudo.

Now we have builded project and we can set rules and run suricata
1. `cd suricata/`
1. ``
1. ``
1. ``
1. ``
1. ``
1. ``
1. ``
1. ``
