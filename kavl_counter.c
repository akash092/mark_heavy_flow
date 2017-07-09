#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>

#define _XOPEN_SOURCE 500 /* Enable certain library functions (strdup) on linux. See feature_test_macros(7) */
#include <limits.h>
#include <assert.h>

#include "avl_modified.h"

#define CLOCKID CLOCK_REALTIME
#define SIG SIGUSR1
timer_t timerid;

void event_handler(int);
int read_socket_fd();
char time_buff[100];

#define MAX_BYTES 5*1000 /* 2*1KB */

struct nfq_handle *h;
struct nfq_q_handle *qh;
int fd;
char buf[4096] __attribute__ ((aligned));

avl_tree_t *tree = avl_create();

static void read_bytes(int sig, siginfo_t *si, void *uc)
{
    FILE *fp;
    char path[1035];
    char system_buf1[1024];
    char system_buf2[1024];

    if(si->si_value.sival_ptr != &timerid){
        printf("Ignore for now\n");
    } else {
        time_t now = time (0);
        strftime (time_buff, 100, "%Y-%m-%d %H:%M:%S", localtime (&now));
        printf("\n\n%s: Timer signal %d expired\n", time_buff,sig);
        fp = popen("iptables -nvxL | grep '*' | grep -v '0.0.0.0' | awk '{print $2,$8,$9}'", "r");
        if (fp == NULL) {
            printf("Failed to run command\n" );
            exit(1);
        }
        while (fgets(path, sizeof(path)-1, fp) != NULL) {
            char *bytes_count, *src, *dst;
            bytes_count = strtok(path," ");
            if (isdigit(bytes_count[0])) {
                if (atoi(bytes_count) > MAX_BYTES) {
                    src = strtok(NULL, " ");
                    dst = strtok(NULL, " ");
                    dst[strlen(dst)-1] = 0;
                    printf("High BW stream found %s %s %s\n",bytes_count,src,dst);
                    sprintf(system_buf1," iptables -t mangle -A OUTPUT -p TCP -s %s -d %s -j DSCP --set-dscp 50",src,dst);
                    printf("%s IP:%s Cmd: %s\n",time_buff,dst,system_buf1);
                    system(system_buf1);
                    sprintf(system_buf2," iptables -D OUTPUT -s %s -d %s -p TCP -j ACCEPT",src,dst);
                    printf("%s IP:%s Cmd: %s\n\n",time_buff,dst,system_buf2);
                    system(system_buf2);
                }
                else {
                    //printf("Still below threshold for: %s\n", path);
                }
            }
            else {
                printf("Something is worng for: %s\n", path);
            }
        }
        pclose(fp);
    }
    printf("\n");
}
static u_int32_t print_pkt (struct nfq_data *tb)
{
        struct in_addr dest_ip_addr;
        struct in_addr src_ip_addr;
		int id = 0;
        int entry;
		struct nfqnl_msg_packet_hdr *ph;
		int ret=0;
		unsigned char *data;
        char system_buf1[1024];
		
        ph = nfq_get_msg_packet_hdr(tb);
		if (ph) {
				id = ntohl(ph->packet_id);
		}
		ret = nfq_get_payload(tb, &data);
		//if (ret >= 0) {
		//		printf("payload_len=%d \n", ret);
		//		for (i=0;i<ret-1;i++) {
		//			printf ("[%d]:%02x ",i,data[i]);
		//		}		
		//}
        struct ip *ip = (struct ip *) data;
        struct tcphdr *tcp = (struct tcphdr *) (ip+1);
        dest_ip_addr.s_addr = ip->ip_dst.s_addr;
        src_ip_addr.s_addr = ip->ip_src.s_addr;
        char dst_ip_str[20], src_ip_str[20]; 
        strcpy(dst_ip_str, inet_ntoa(dest_ip_addr));
        strcpy(src_ip_str, inet_ntoa(src_ip_addr));
        time_t now = time (0);
        strftime (time_buff, 100, "%Y-%m-%d %H:%M:%S", localtime (&now));
        printf("%s Dest_IP:%s src_port %d dst_port %d tcp_flags 0x%x\n", time_buff, dst_ip_str, ntohs(tcp->th_sport), ntohs(tcp->th_dport), tcp->th_flags);

        if (tcp->th_flags == 0x02) {
            if (!avl_find(tree, ip->ip_dst.s_addr)) { /*No existing entry*/
                printf("%s Dest_IP:%s Received SYN: Adding new IP entry in Database\n", time_buff, dst_ip_str);
                avl_insert(tree, ip->ip_dst.s_addr);
                sprintf(system_buf1,"iptables -A OUTPUT -s %s -d %s -p TCP -j ACCEPT",src_ip_str,dst_ip_str);
		        printf("%s Src_IP:%s Dst_IP:%s Cmd: %s\n\n",time_buff, src_ip_str, dst_ip_str, system_buf1);
                system(system_buf1);
            } else {
                printf("%s Ignoring repetitive SYNs for Dest %s\n\n", time_buff,dst_ip_str);
            }
        }
        else {
            printf("Should not HIT\n");
        }
		return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
				struct nfq_data *nfa, void *data)
{
		u_int32_t id = print_pkt(nfa);
		//printf("entering callback\n");
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
		//struct nfnl_handle *nh;
        struct sigevent sev;
        struct itimerspec its;
        //long long freq_nanosecs;
        //sigset_t mask;
        struct sigaction sa;
        //Signal Handler
        signal (SIGQUIT, event_handler);
        signal (SIGINT, event_handler);

		printf("opening library handle\n");
		h = nfq_open();
		if (!h) {
				fprintf(stderr, "error during nfq_open()\n");
				exit(1);
		}

		printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
		if (nfq_unbind_pf(h, AF_INET) < 0) {
				fprintf(stderr, "error during nfq_unbind_pf()\n");
				exit(1);
		}

		printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
		if (nfq_bind_pf(h, AF_INET) < 0) {
				fprintf(stderr, "error during nfq_bind_pf()\n");
				exit(1);
		}

		printf("binding this socket to queue '0'\n");
		qh = nfq_create_queue(h,  0, &cb, NULL);
		if (!qh) {
				fprintf(stderr, "error during nfq_create_queue()\n");
				exit(1);
		}

		printf("setting copy_packet mode\n");
		if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
				fprintf(stderr, "can't set packet_copy mode\n");
				exit(1);
		}
        printf("Establishing handler for signal %d\n", SIG);
        sa.sa_flags = SA_SIGINFO;
        sa.sa_sigaction = read_bytes;
        sigemptyset(&sa.sa_mask);
        sigaction(SIG, &sa, NULL);

        sev.sigev_notify = SIGEV_SIGNAL;
        sev.sigev_signo = SIG;
        sev.sigev_value.sival_ptr = &timerid;
        timer_create(CLOCKID, &sev, &timerid);
        /* Start the timer */

        its.it_value.tv_sec = 1;
        its.it_value.tv_nsec = 0;
        its.it_interval.tv_sec = its.it_value.tv_sec;
        its.it_interval.tv_nsec = its.it_value.tv_nsec;
        timer_settime(timerid, 0, &its, NULL);
		
        fd = nfq_fd(h);
         
		printf(" \n\n\n");
		/*while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
				printf("ncedkfjnvdfj \n\n\n");
				nfq_handle_packet(h, buf, rv);
		}*/
        while (1) {
            read_socket_fd();
        }
        printf("SHould not come here\n");
		exit(EXIT_FAILURE);
}
int read_socket_fd() {
    int rv;
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
          nfq_handle_packet(h, buf, rv);
    }
    return 0;
}
void  event_handler(int sig)
{
    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);
    printf("closing library handle\n");
    nfq_close(h);
    //Print iptables and mangle entries before flushing
    printf("Current iptables rule before flushing\n");
    system("iptables -L -n");
    printf("Current mangle table rule before flushing\n");
    system("iptables -t mangle -L -n");
    //Flush all rules
    system("iptables -t mangle -F");
    system("iptables -F");
    exit(0);
}
