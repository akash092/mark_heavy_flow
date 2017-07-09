# mark_heavy_flow
#Please use g++ since gcc fails to compile


Insert rule : iptables -A OUTPUT -s <machine_ip_address_> -p tcp --tcp-flags ALL SYN -j NFQUEUE

1) g++ -c -o avl_modified.o avl_modified.c
2) g++ -c -o kavl_counter.o kavl_counter.c
3) g++ -Wall -o run_main kavl_counter.o avl_modified.o -lnfnetlink -lnetfilter_queue -lrt
4) ./run_main
        which should output as: 

        opening library handle
        unbinding existing nf_queue handler for AF_INET (if any)
        binding nfnetlink_queue as nf_queue handler for AF_INET
        binding this socket to queue '0'
        setting copy_packet mode
        Establishing handler for signal 10

PS: Please check akash_task_report.pdf for full documentation and results & validation. 
