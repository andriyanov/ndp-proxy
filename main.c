/*  Copyright (C) 2011  P.D. Buchan (pdbuchan@yahoo.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Receive an IPv6 router advertisement and extract
// various information stored in the ethernet frame.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netinet/icmp6.h>
#include <netinet/in.h>       // IPPROTO_IPV6, IPPROTO_ICMPV6
#include <netinet/ip.h>       // IP_MAXPACKET (65535)
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <net/if.h>           // struct ifreq
#include <bits/socket.h>      // structs msghdr and cmsghdr

int sd; // socket descriptor
int ifindex;
struct in6_addr source; // the link-local address of this machine

// Taken from <linux/ipv6.h>, also in <netinet/in.h>
struct in6_pktinfo {
	struct in6_addr ipi6_addr;
	int             ipi6_ifindex;
};

	char * 
format_ip6 (struct in6_addr *paddr)
{
	char *ret = malloc (40);
	inet_ntop (AF_INET6, paddr, ret, 40);
	return ret;
}

// Checksum function
unsigned short int checksum (unsigned short int *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short int *w = addr;
	unsigned short int answer = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= sizeof (unsigned short int);
	}

	if (nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;

	return (answer);
}

int send_nd_redirect (struct in6_addr *dst, struct in6_addr *target)
{
	static const int hoplimit = 255;
	struct msghdr msghdr;
	struct cmsghdr *cmsghdr1, *cmsghdr2;
	struct in6_pktinfo *pktinfo;
	struct iovec iov;
	struct sockaddr_in6 destination;

	struct {
		// IPv6 pseudo-header to compute the ICMPv6 checksum
		struct in6_addr psrc;
		struct in6_addr pdst;
		uint32_t pupper_len;
		uint8_t dummy[3];
		uint8_t pproto;

		// ICMPv6 redirect packet
		struct nd_redirect icmp_pkt;
	} opkt; // TODO: __attribute__ ((packed));

	memset (&opkt, 0, sizeof (opkt));
	opkt.psrc = source;
	opkt.pdst = *dst;
	opkt.pupper_len = htonl (sizeof (struct nd_redirect));
	opkt.pproto = IPPROTO_IPV6;
	opkt.icmp_pkt.nd_rd_hdr.icmp6_type = ND_REDIRECT;
	opkt.icmp_pkt.nd_rd_hdr.icmp6_code = 0;
	opkt.icmp_pkt.nd_rd_target = *target;
	opkt.icmp_pkt.nd_rd_dst = source;
	opkt.icmp_pkt.nd_rd_hdr.icmp6_cksum = checksum ((unsigned short int *) &opkt, sizeof (opkt));

	// prepare destination
	memset (&destination, 0, sizeof (destination));
	memcpy (&destination.sin6_addr, dst, sizeof (*dst));
	destination.sin6_family = AF_INET6;

	// Prepare msghdr for sendmsg().

	memset (&msghdr, 0, sizeof (msghdr));
	msghdr.msg_name = &destination;  // Destination IPv6 address as struct sockaddr_in6
	msghdr.msg_namelen = sizeof (destination);
	memset (&iov, 0, sizeof (iov));
	iov.iov_base = (unsigned char *) &opkt.icmp_pkt;  // Point msghdr to packet buffer
	iov.iov_len = sizeof (opkt.icmp_pkt);
	msghdr.msg_iov = &iov;                 // scatter/gather array
	msghdr.msg_iovlen = 1;                // number of elements in scatter/gather array

	// Tell msghdr we're adding cmsghdr data to change hop limit and specify interface.
	// Allocate some memory for our cmsghdr data.
	int cmsglen = CMSG_SPACE (sizeof (int)) + CMSG_SPACE (sizeof (struct in6_pktinfo));
	if (NULL == (msghdr.msg_control = (unsigned char *) malloc (cmsglen * sizeof (unsigned char)))) {
		fprintf (stderr, "ERROR: Cannot allocate memory for array 'msghdr.msg_control'.\n");
		exit (EXIT_FAILURE);
	}
	memset (msghdr.msg_control, 0, cmsglen);
	msghdr.msg_controllen = cmsglen;

	// Change hop limit to 255 as required for neighbor advertisement (RFC 4861).
	cmsghdr1 = CMSG_FIRSTHDR (&msghdr);
	cmsghdr1->cmsg_level = IPPROTO_IPV6;
	cmsghdr1->cmsg_type = IPV6_HOPLIMIT;  // We want to change hop limit
	cmsghdr1->cmsg_len = CMSG_LEN (sizeof (int));
	*((int *) CMSG_DATA (cmsghdr1)) = hoplimit;  // Copy pointer to int hoplimit

	// Specify source interface index for this packet via cmsghdr data.
	cmsghdr2 = CMSG_NXTHDR (&msghdr, cmsghdr1);
	cmsghdr2->cmsg_level = IPPROTO_IPV6;
	cmsghdr2->cmsg_type = IPV6_PKTINFO;  // We want to specify interface here
	cmsghdr2->cmsg_len = CMSG_LEN (sizeof (struct in6_pktinfo));
	pktinfo = (struct in6_pktinfo *) CMSG_DATA (cmsghdr2);
	pktinfo->ipi6_ifindex = ifindex;
	pktinfo->ipi6_addr = source;

	int ret = 1;
	if (sendmsg (sd, &msghdr, 0) < 0) {
		perror ("sendmsg");
		ret = 0;
	}
	free (msghdr.msg_control);

	return ret;
}

int main (int argc, char **argv)
{
	struct nd_neighbor_solicit *ns;
	unsigned char inpack[IP_MAXPACKET];
	struct ifreq ifr;

	// Interface to receive packet on.
	int iArg = 1;
	if (iArg >= argc) {
		fprintf (stderr, "Expecting interface name as argument\n");
		exit (EXIT_FAILURE);
	}
	strncpy (ifr.ifr_name, argv[iArg++], sizeof(ifr.ifr_name)); //TODO

#define SRC_ADDR "fe80::b299:28ff:fec8:f036"
	switch (inet_pton (AF_INET6, SRC_ADDR, &source))
	{
		case 1:
			break;
		case -1:
			perror ("inet_pton");
			exit (EXIT_FAILURE);
		default:
			fprintf (stderr, "Invalid address `%s'\n", SRC_ADDR);
			exit (EXIT_FAILURE);
	};

	// zero memory for input packet
	memset (inpack, 0, sizeof (inpack));

	// Request a socket descriptor sd.
	if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
		perror ("socket");
		exit (EXIT_FAILURE);
	}

	// filter only ICMPv6 NS messages
	struct icmp6_filter filter;
	ICMP6_FILTER_SETBLOCKALL (&filter);
	ICMP6_FILTER_SETPASS (ND_NEIGHBOR_SOLICIT, &filter);
	if (setsockopt (sd, SOL_RAW, ICMP6_FILTER, (void *) &filter, sizeof (filter)) < 0) {
		/* ICMPv6 filtering is not supported for now */
	}

	// Retrieve source interface index.
	if ((ifindex = if_nametoindex (ifr.ifr_name)) == 0) {
		fprintf (stderr, "if_nametoindex %s: ", ifr.ifr_name);
		perror (NULL);
		exit (EXIT_FAILURE);
	}

	// Bind socket to specified interface
	if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof (ifr)) < 0) {
		perror ("SO_BINDTODEVICE");
		exit (EXIT_FAILURE);
	}

	// Listen for incoming message from socket sd.
	ns = (struct nd_neighbor_solicit *) inpack;
	struct sockaddr_in6 src;
	int len;
	while (1) {
		socklen_t src_buff = sizeof (src);
		if ((len = recvfrom (sd, inpack, IP_MAXPACKET, 0, (struct sockaddr*) &src, &src_buff)) < 0) {
			perror ("recvfrom failed ");
			return (EXIT_FAILURE);
		}
		if (len >= sizeof(*ns) && ns->nd_ns_hdr.icmp6_type == ND_NEIGHBOR_SOLICIT) {
			printf ("got NS from %s for %s\n", format_ip6 (&src.sin6_addr), format_ip6 (&ns->nd_ns_target));
			if (send_nd_redirect (&src.sin6_addr, &ns->nd_ns_target))
				printf ("sent redirect\n");
		}
	}

	close (sd);

	return (EXIT_SUCCESS);
}

