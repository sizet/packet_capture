// ©.
// https://github.com/sizet/packet_capture

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>




#ifndef PACKET_AUXDATA
#error "must be support PACKET_AUXDATA (since linux 2.6.21)"
#endif




#define DMSG(msg_fmt, msg_args...) \
    printf("%s(%04u): " msg_fmt "\n", __FILE__, __LINE__, ##msg_args)




struct pcap_hdr
{
    __u32 magic_number;
    __u16 version_major;
    __u16 version_minor;
    __s32 thiszone;
    __u32 sigfigs;
    __u32 snaplen;
    __u32 network;
};

struct pcaprec_hdr
{
    __u32 ts_sec;
    __u32 ts_usec;
    __u32 incl_len;
    __u32 orig_len;
};

#define VLAN_HLEN 4

struct vlan_ethhdr
{
    __u8 h_dest[ETH_ALEN];
    __u8 h_source[ETH_ALEN];
    __be16 h_vlan_proto;
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
} __attribute__((packed));




int shutdown_process = 0;
unsigned long long int recv_pkts = 0, recv_bytes = 0, send_pkts = 0, send_bytes = 0;




void signal_handle(
    int signal_value)
{
    switch(signal_value)
    {
        case SIGINT:
        case SIGQUIT:
        case SIGTERM:
            shutdown_process = 1;
            break;
        case SIGUSR1:
            DMSG("recv = %llu packets, %llu bytes", recv_pkts, recv_bytes);
            DMSG("send = %llu packets, %llu bytes", send_pkts, send_bytes);
            break;
    }

    return;
}

int add_pid_file(
    char *file_path)
{
    FILE *file_fp;


    if(file_path != NULL)
    {
        file_fp = fopen(file_path, "w");
        if(file_fp == NULL)
        {
            DMSG("call fopen(%s) fail [%s]", file_path, strerror(errno));
            return -1;
        }
        fprintf(file_fp, "%d", getpid());
        fclose(file_fp);
    }

    return 0;
}

int del_pid_file(
    char *file_path)
{
    if(file_path != NULL)
        if(unlink(file_path) == -1)
        {
            DMSG("call unlink(%s) fail [%s]", file_path, strerror(errno));
            return -1;
        }

    return 0;
}

int pcap_init(
    char *file_path,
    FILE **filefp_buf)
{
    FILE *file_fp;
    struct pcap_hdr pcap_fhdr;

    file_fp = fopen(file_path, "wb");
    if(file_fp == NULL)
    {
        DMSG("call fopen(%s) fail [%s]", file_path, strerror(errno));
        return -1;
    }

    memset(&pcap_fhdr, 0, sizeof(pcap_fhdr));
    pcap_fhdr.magic_number = htonl(0xA1B2C3D4);
    pcap_fhdr.version_major = htons(2);
    pcap_fhdr.version_minor = htons(4);
    pcap_fhdr.thiszone = htonl(0);
    pcap_fhdr.sigfigs = htonl(0);
    pcap_fhdr.snaplen = htonl(65535);
    pcap_fhdr.network = htonl(1);
    fwrite(&pcap_fhdr, 1, sizeof(pcap_fhdr), file_fp);

    *filefp_buf = file_fp;

    return 0;
}

int socket_init(
    char *if_name,
    int *sockfd_buf)
{
    int sock_fd, opt_flag;
    struct sockaddr_ll sock_addrll;
    struct ifreq if_req;


    sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock_fd == -1)
    {
        DMSG("call socket() fail [%s]", strerror(errno));
        goto FREE_01;
    }

    // 需要封包的 timestamp 資料.
    opt_flag = 1;
    if(setsockopt(sock_fd, SOL_SOCKET, SO_TIMESTAMP, &opt_flag, sizeof(opt_flag)) == -1)
    {
        DMSG("call setsockopt(SOL_SOCKET, SO_TIMESTAMP) fail [%s]", strerror(errno));
        goto FREE_02;
    }

    // 需要封包的 VLAN 資料.
    opt_flag = 1;
    if(setsockopt(sock_fd, SOL_PACKET, PACKET_AUXDATA, &opt_flag, sizeof(opt_flag)) == -1)
    {
        DMSG("call setsockopt(SOL_PACKET, PACKET_AUXDATA) fail [%s]", strerror(errno));
        goto FREE_02;
    }

    memset(&if_req, 0, sizeof(if_req));
    snprintf(if_req.ifr_name, sizeof(if_req.ifr_name), "%s", if_name);
    if(ioctl(sock_fd, SIOCGIFINDEX, &if_req) == -1)
    {
        DMSG("call ioctl(SIOCGIFINDEX, %s) fail [%s]", if_req.ifr_name, strerror(errno));
        goto FREE_02;
    }

    memset(&sock_addrll, 0, sizeof(sock_addrll));
    sock_addrll.sll_family = AF_PACKET;
    sock_addrll.sll_ifindex = if_req.ifr_ifindex;
    sock_addrll.sll_protocol = htons(ETH_P_ALL);

    if(bind(sock_fd, (struct sockaddr *) &sock_addrll, sizeof(sock_addrll)) == -1)
    {
        DMSG("call bind() fail [%s]", strerror(errno));
        goto FREE_02;
    }

    *sockfd_buf = sock_fd;

    return 0;
FREE_02:
    close(sock_fd);
FREE_01:
    return -1;
}

int main(
    int argc,
    char **argv)
{
    char opt_key, *if_name = NULL, *file_path = NULL, *pid_path = NULL;
    FILE *file_fp;
    int sock_fd;
    fd_set sock_set;
    struct sockaddr_ll sock_addrll;
    struct iovec io_vec;
    struct msghdr msg_hdr;
    struct cmsghdr *cmsg_hdr;
    struct timeval *tv_data;
    struct tpacket_auxdata *aux_data;
    struct vlan_ethhdr *eth_vlan_hdr;
    struct pcaprec_hdr pcap_phdr;
    __u8 msg_buf[CMSG_SPACE(sizeof(struct timeval) + sizeof(struct tpacket_auxdata))];
    __u8 pkt_buf[65536], *pkt_data, *pkt_loc;
    size_t pkt_size;
    ssize_t rlen;


    while((opt_key = getopt(argc , argv, "i:c:p:")) != -1)
        switch(opt_key)
        {
            case 'i':
                if_name = optarg;
                break;
            case 'c':
                file_path = optarg;
                break;
            case 'p':
                pid_path = optarg;
                break;
        }

    if(if_name == NULL)
        goto FREE_HELP;
    if(file_path == NULL)
        goto FREE_HELP;


    if(add_pid_file(pid_path) < 0)
    {
        DMSG("call add_pid_file() fail");
        goto FREE_01;
    }

    signal(SIGINT, signal_handle);
    signal(SIGQUIT, signal_handle);
    signal(SIGTERM, signal_handle);
    signal(SIGUSR1, signal_handle);
    signal(SIGPIPE, SIG_IGN);

    if(pcap_init(file_path, &file_fp) < 0)
    {
        DMSG("call pcap_init() fail");
        goto FREE_02;
    }

    if(socket_init(if_name, &sock_fd) < 0)
    {
        DMSG("call socket_init() fail");
        goto FREE_03;
    }

    // 在封包緩衝開頭預留空間給 VLAN 標頭.
    pkt_data = pkt_buf + VLAN_HLEN;
    pkt_size = sizeof(pkt_buf) - VLAN_HLEN;

    // 使用 recvmsg() 接收封包和輔助資料 (ancillary data).
    memset(&io_vec, 0, sizeof(io_vec));
    io_vec.iov_base = pkt_data;
    io_vec.iov_len = pkt_size;
    memset(&msg_hdr, 0, sizeof(msg_hdr));
    msg_hdr.msg_name = &sock_addrll;
    msg_hdr.msg_namelen = sizeof(sock_addrll);
    msg_hdr.msg_iov = &io_vec;
    msg_hdr.msg_iovlen = 1;
    msg_hdr.msg_control = msg_buf;
    msg_hdr.msg_controllen = sizeof(msg_buf);

    while(shutdown_process == 0)
    {
        FD_ZERO(&sock_set);
        FD_SET(sock_fd, &sock_set);

        if(select(sock_fd + 1, &sock_set, NULL, NULL, NULL) == -1)
        {
            if(errno == EINTR)
                continue;
            DMSG("call select() fail [%s]", strerror(errno));
            goto FREE_04;
        }

        if(FD_ISSET(sock_fd, &sock_set) == 0)
            continue;

        rlen = recvmsg(sock_fd, &msg_hdr, 0);
        if(rlen == -1)
        {
            DMSG("call recvmsg() fail [%s]", strerror(errno));
            if(errno == ENETDOWN)
                continue;
            goto FREE_04;
        }

        // 取出輔助資料.
        tv_data = NULL;
        aux_data = NULL;
        for(cmsg_hdr = CMSG_FIRSTHDR(&msg_hdr); cmsg_hdr != NULL;
            cmsg_hdr = CMSG_NXTHDR(&msg_hdr, cmsg_hdr))
        {
            // timestamp 資料.
            if(cmsg_hdr->cmsg_level == SOL_SOCKET)
                if(cmsg_hdr->cmsg_type == SCM_TIMESTAMP)
                    if(cmsg_hdr->cmsg_len >= CMSG_LEN(sizeof(struct timeval)))
                    {
                        tv_data = (struct timeval *) CMSG_DATA(cmsg_hdr);
                        continue;
                    }

            // VLAN 資料.
            if(cmsg_hdr->cmsg_level == SOL_PACKET)
                if(cmsg_hdr->cmsg_type == PACKET_AUXDATA)
                    if(cmsg_hdr->cmsg_len >= CMSG_LEN(sizeof(struct timeval)))
                    {
                        aux_data = (struct tpacket_auxdata *) CMSG_DATA(cmsg_hdr);
                        continue;
                    }
        }

        pkt_loc = pkt_data;

        // 將 VLAN 資料塞入封包的 VLAN 標頭部分.
        if(aux_data != NULL)
            if(aux_data->tp_vlan_tci != 0)
            {
                memmove(pkt_loc - VLAN_HLEN, pkt_loc, ETH_ALEN * 2);
                pkt_loc -= VLAN_HLEN;
                rlen += VLAN_HLEN;

                eth_vlan_hdr = (struct vlan_ethhdr *) pkt_loc;
                eth_vlan_hdr->h_vlan_proto = htons(ETH_P_8021Q);
                eth_vlan_hdr->h_vlan_TCI = htons(aux_data->tp_vlan_tci);
            }

        if(sock_addrll.sll_pkttype == PACKET_OUTGOING)
        {
            send_pkts++;
            send_bytes += rlen;
        }
        else
        {
            recv_pkts++;
            recv_bytes += rlen;
        }

        pcap_phdr.ts_sec = htonl(tv_data->tv_sec);
        pcap_phdr.ts_usec = htonl(tv_data->tv_usec);
        pcap_phdr.incl_len = pcap_phdr.orig_len = htonl(rlen);

        fwrite(&pcap_phdr, sizeof(pcap_phdr), 1, file_fp);
        fwrite(pkt_loc, sizeof(__u8), rlen, file_fp);
    }

    DMSG("recv = %llu packets, %llu bytes", recv_pkts, recv_bytes);
    DMSG("send = %llu packets, %llu bytes", send_pkts, send_bytes);

FREE_04:
    close(sock_fd);
FREE_03:
    fclose(file_fp);
FREE_02:
    del_pid_file(pid_path);
FREE_01:
    return 0;
FREE_HELP:
    printf("\npcaket_capture argument-list\n");
    printf("  argument :\n");
    printf("    <-i ethernet-interface-name>\n");
    printf("      capture the packet of this network interface.\n");
    printf("      ex : -i eth0\n");
    printf("    <-c file-path>\n");
    printf("      save captured packet to this file (pcap format).\n");
    printf("      ex : -c packet.pcap\n");
    printf("    [-p file-path]\n");
    printf("      save process id to this file.\n");
    printf("      ex : -p /var/run/pcaket_capture.pid\n");
    printf("  signal control :\n");
    printf("    SIGINT, SIGQUIT, SIGTERM\n");
    printf("      stop process.\n");
    printf("    SIGUSR1\n");
    printf("      show captured packet counter.\n\n");
    return 0;
}
