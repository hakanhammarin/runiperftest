# runiperftest
Prereq:
install iperf

yum -y install epel-release && yum -y install iperf

install git
yum -y install git

Create an repository
mkdir /root/github
cd /root/github
git init

git clone https://github.com/hakanhammarin/runiperftest

cd runiperftest
chmod +x runiperftest.sh

start iperf on each host:
iperf -s &


RUN:
./runiperftest.sh 


..[ ID] Interval       Transfer     Bandwidth
[  3]  0.0-30.0 sec  29.5 GBytes  8.46 Gbits/sec
[  6]  0.0-30.0 sec  29.3 GBytes  8.39 Gbits/sec
[  4]  0.0-30.0 sec  29.4 GBytes  8.41 Gbits/sec
[  5]  0.0-30.0 sec  29.5 GBytes  8.43 Gbits/sec
[SUM]  0.0-30.0 sec   118 GBytes  33.7 Gbits/sec
[ ID] Interval       Transfer     Bandwidth
[  7]  0.0-30.0 sec  29.3 GBytes  8.39 Gbits/sec
[  5]  0.0-30.1 sec  29.4 GBytes  8.41 Gbits/sec
[  4]  0.0-30.1 sec  29.5 GBytes  8.44 Gbits/sec
[  6]  0.0-30.1 sec  29.5 GBytes  8.42 Gbits/sec
[SUM]  0.0-30.1 sec   118 GBytes  33.6 Gbits/sec

Individual TP:
127.0.0.1 -> 127.0.0.1 : 33.7 Gbits/sec

IPerf Servers # : 1, TP : 33.7 Gbits/sec
