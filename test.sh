#!/bin/bash


function run_test () {
   ./trace $file > test_out
   diff -B --ignore-all-space test_out $file.out > diff_out
   
   if ! [ -s diff_out ] 
   then
      printf "$file good\n"
      cat diff_out
   else
      printf "Error on $file\n"
      diff -B --ignore-all-space test_out $file.out > $file.diff_out
      ./trace $file > $file.user_out
   fi

   rm diff_out
   rm test_out
}

make clean
make

printf "Testing Trace\n\n"

#arp
file=given/arp/ArpTest.pcap
run_test

#ip
file=given/ip/IP_bad_checksum.pcap
run_test

#ping
file=given/PingTest.pcap
run_test

#http
file=given/http/Http.pcap
run_test

#tcp
file=given/tcp/smallTCP.pcap
run_test

file=given/tcp/TCP_bad_checksum.pcap
run_test

#udp
file=given/udp/UDPfile.pcap
run_test

#mix
file=given/mix/largeMix.pcap
run_test

file=given/mix/largeMix2.pcap
run_test

file=given/mix/mix_withIPoptions.pcap
run_test






