# runiperftest
Prereq:
install iperf
yum -y install epel-release
yum -y install iperf

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

./runiperftest.sh 


