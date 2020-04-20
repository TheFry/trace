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
file=given/ArpTest.pcap
run_test

#ip
file=given/IP_bad_checksum.pcap
run_test

#ping
file=given/PingTest.pcap
run_test

#http
file=given/Http.pcap
run_test

#tcp
file=given/smallTCP.pcap
run_test

file=given/TCP_bad_checksum.pcap
run_test

#udp
file=given/UDPfile.pcap
run_test

#mix
file=given/largeMix.pcap
run_test

file=given/largeMix2.pcap
run_test

file=given/mix_withIPoptions.pcap
run_test






