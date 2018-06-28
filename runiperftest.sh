#!/bin/bash
#
THREADS=4
TIME=30

# remove loggs
rm -rf *log

for LINE in `cat vm.list`
do
    SERVER=`echo $LINE | cut -f2 -d","`
    CLIENT=`echo $LINE | cut -f1 -d","` 

# Start iperf
    ssh $CLIENT "iperf -c $SERVER -P $THREADS -t $TIME -f g" | tee $SERVER.log &
done

# loop
while [ 1 ]
do
    sleep 10
    RUNNING=`ps -ef | grep -c "iperf -c"`
    if [ $RUNNING -le 1 ]; then
        break;
    fi
    echo -n "."
done

# Print
echo
echo "Individual TP:"
for LOG in `ls -1 *log`
do
    SERVER_IP=`echo $LOG | sed -e 's/.log//'`
    FLOW=`grep $SERVER_IP vm.list | sed -e 's/,/ -> /g'`
    TP=`grep SUM $LOG | awk '{ print $6" "$7 }'`
    echo "$FLOW : $TP"
done

#Print 
TP=`tail -n 1 *.log | grep SUM | awk '{ sum+=$6 } END { print sum }'`
echo
echo "IPerf Servers # : `ls -1 *.log | wc -l`, TP : $TP Gbits/sec"
