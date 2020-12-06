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
1. `sudo pip install --upgrade suricata-update`
1. `git clone https://github.com/yerseg/suricata.git`
1. `cd suricata/`
1. `git checkout yerseg/s7comm_investigation`
1. `git clone https://github.com/OISF/libhtp.git`
1. `sudo ./autogen.sh`
1. `sudo ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var`
1. `sudo mkdir /var/log/suricata`
1. `sudo mkdir /etc/suricata`
1. `sudo make && sudo make install && sudo make install-conf`
1. `sudo cp suricata.yaml /etc/suricata`
1. `sudo suricata-update -D /etc/suricata`
1. `sudo ifconfig lo mtu 1522`

After each edits in .c and .h src files run `sudo make install`

Install testing stend for S7
1. `cd ~`
1. `git clone https://github.com/yerseg/s7comm_investigation.git`
1. `cd s7comm_investigation/`
1. `sudo cp ./libsnap7.so /usr/lib`
1. `sudo ldconfig`
1. Now you can run server and client by python3. Don't forget use sudo.

Edit rules and configs
- `sudo gedit /etc/suricata/suricata.yaml` -- set interface to `lo`
- You can edit rules `sudo gedit /etc/suricata/rules/suricata.rules`

Now we can run suricata `sudo suricata -c /etc/suricata/suricata.yaml -i lo --set capture.disable-offloading=false`
Use Wireshark to check packets.

Our test rule
`alert tcp 127.0.0.1 any -> 127.0.0.100 any (s7comm: function 4;)`

#### How to check Suricata alerts?
`sudo cat /var/log/suricata/eve.json | grep "\"event_type\":\"s7comm\""`
