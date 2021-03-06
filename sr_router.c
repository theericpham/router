/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include <stdlib.h>
#include <string.h>

/*---------------------------------------------------------------------
 * Declaration of Constants
 *
 *---------------------------------------------------------------------*/

#define IP_VERSION_4   4
#define IP_HEADER_LEN  5
#define IP_DEFAULT_TTL 64

#define ICMP_TYPE_ECHO_REQ         8
#define ICMP_CODE_ECHO_REQ         0
#define ICMP_TYPE_ECHO_REPLY       0
#define ICMP_CODE_ECHO_REPLY       0
#define ICMP_TYPE_TTL_EXP          11
#define ICMP_CODE_TTL_EXP          0
#define ICMP_TYPE_UNREACHABLE		  3
#define ICMP_CODE_PORT_UNREACHABLE 3
#define ICMP_CODE_NET_UNREACHABLE  0

/*---------------------------------------------------------------------
 * Declaration of Helper Functions
 *
 *---------------------------------------------------------------------*/

/* 
 *  Set ethernet frame for a packet by filling in MAC addresses and send the packet 
 */
int frameAndSendPacket(struct Instance* sr, uint8_t* packet, char* interface_name, unsigned int length, unsigned char* mac, enum Ethertype packet_ethertype) {
  /* get the interface to forward from */
  struct EthernetHeader* frame = (struct EthernetHeader*) packet;
  struct Interface* interface  = getInterface(sr, interface_name);

  /* set MAC addresses */
  memcpy(frame->ether_dhost, mac, ETHERNET_ADDRESS_LENGTH);              /* dest specified by args */
  memcpy(frame->ether_shost, interface->addr, ETHERNET_ADDRESS_LENGTH);  /* src is interface MAC address */
  
  frame->ether_type = htons(packet_ethertype);
  
  fprintf(stderr, "*** Modified Ethernet Header\n");
  printEthernetHeader(packet);
  
  fprintf(stderr, "*** Sending Raw Frame\n");
  printHeaders(packet, length);
    
  sendPacket(sr, packet, length, interface_name);	
  fprintf(stderr, "*** Sent Raw Frame\n");
  return 0;
}

int makeIpPacket(struct Instance* sr, uint32_t destination_ip, uint8_t* data, int length, char* interface) {
	struct IpHeader* ip_header = (struct IpHeader*)(data + ETHERNET_HEADER_LENGTH);
	ip_header->ip_v   = IP_VERSION_4;
	ip_header->ip_hl  = IP_HEADER_LEN;
	ip_header->ip_tos = 0;
	ip_header->ip_len = htons(length - ETHERNET_HEADER_LENGTH);
	ip_header->ip_id  = htons(0);
	ip_header->ip_off = htons(IP_DF);
	ip_header->ip_ttl = IP_DEFAULT_TTL;
	/* Specific things for this packet */
	struct Interface* source_interface = getInterface(sr, interface);
	ip_header->ip_dst = destination_ip;
	ip_header->ip_src = source_interface->ip;
	
	/* compute ip header checksum */
	ip_header->ip_sum = 0;
	ip_header->ip_sum = checksum(data + ETHERNET_HEADER_LENGTH, IP_HEADER_LENGTH);
	return 0;
  
  fprintf(stderr, "*** Modified IP Header\n");
  printIpHeader((uint8_t*) ip_header);
}

int sendIp(struct Instance* sr, uint32_t destination_ip, uint8_t* data, int length, char* interface) {
	struct IpHeader* ip_header = (struct IpHeader*)(data + IP_OFFSET);
	ip_header->ip_sum = 0;
	ip_header->ip_sum = checksum(ip_header, IP_HEADER_LENGTH);
	
	/* Next look up the route to the destination IP */
	struct RoutingTable* route = findLpmRoute(sr, ntohl(destination_ip));
	if (!route){
    sendIcmp(sr, ip_header->ip_src, ICMP_TYPE_UNREACHABLE, ICMP_CODE_NET_UNREACHABLE, 0, interface);
	  return -1;
	}
	/* The only thing we'll be using from this route is which one of our interfaces it uses. */
	char* sending_interface = route->interface;
	
	/* Now see if the address for this destination is in our ARP cache */
	struct ArpEntry* arp_entry = arpCacheLookup(&(sr->cache), destination_ip);
	if (arp_entry) {
		frameAndSendPacket(sr, data, sending_interface, length, arp_entry->mac, ethertype_ip);
		free(arp_entry);
	}
	else {
		/* queue and handle arp request if no entry exists */
		struct ArpRequest* arp_request = arpCacheQueueRequest(&(sr->cache), destination_ip, data, length, sending_interface);
		arp_request->interface = sending_interface;
		handleArpRequest(sr, arp_request);
	}
	return 0; /* We're done! */
}

/* 
 *  Send an ICMP message with type and code fields to dest from router interface 
 */
int sendIcmp(struct Instance* sr, uint32_t destination_ip, uint8_t type, uint8_t code, uint8_t* original_packet, char* interface) {
  fprintf(stderr, "*** Sending ICMP to Address %i with Type %i, Code %i\n", destination_ip, type, code);
	/* construct headers */
	uint8_t* response_packet = (uint8_t*) malloc(ICMP_TOTAL_LENGTH);
    
  makeIpPacket(sr, destination_ip, response_packet, ICMP_TOTAL_LENGTH, interface);
  struct IpHeader* ip_header = (struct IpHeader*) (response_packet + IP_OFFSET);
  ip_header->ip_p = ipProtocol_icmp;
  
	/* Now the ICMP payload is the entire IP header of the packet that caused the ICMP + the first 8 bytes of data */
	if ( original_packet )
		memcpy(response_packet + ICMP_PAYLOAD_OFFSET, original_packet + ETHERNET_HEADER_LENGTH, IP_HEADER_LENGTH + ICMP_SAMPLE_LENGTH);
	else /* If no packet pointer, it's not needed; fill with 0 -- probably not necessary */
		memset(response_packet + ICMP_PAYLOAD_OFFSET, 0, IP_HEADER_LENGTH + ICMP_SAMPLE_LENGTH);
  
   /* Now that we've copied the original packet, we can set up the ICMP header and compute the checksum */
	struct IcmpHeader* icmp_header = (struct IcmpHeader*) (response_packet + ICMP_OFFSET);
	icmp_header->icmp_type = type;
	icmp_header->icmp_code = code;
   icmp_header->icmp_sum  = 0;
	icmp_header->icmp_sum  = checksum(response_packet + ICMP_OFFSET, ICMP_PACKET_LENGTH);

	/* Pass the packet to sendIp, which will take care of the IP header formatting and look up the destination in the ARP cache
	Return whatever status this function returns. */
  
	return sendIp(sr, destination_ip, response_packet, ICMP_TOTAL_LENGTH, interface);
}

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct Instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    arpCacheInit(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), arpCacheTimeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: handlePacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void handlePacket(struct Instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  printHeaders(packet, len);

  /*First need to figure out what protocol is running above Ethernet here.*/
  uint16_t ether_type = ethertype(packet);
    
  switch ( ether_type ) {
    case ethertype_ip :
      printf("*** Handling IP packet\n");
      handleIpPacket(sr, packet, len, interface);
      break;
    case ethertype_arp :
      printf("*** Handling ARP packet\n");
      handleArpPacket(sr, packet, len, interface);
      break;
    default:
      printf("*** Unrecognized protocol %x \n", ether_type);
      /* TODO: Error response, maybe ICMP? */
      break;
  }
}/* end handlePacket */

int ipChecksumCorrect(struct IpHeader* ip_header) {
	/* This simple function computes the checksum, compares with received checksum, and restores it */
	uint16_t checksum_received = ip_header->ip_sum;
	ip_header->ip_sum = 0;
	uint16_t checksum_computed = checksum(ip_header, IP_HEADER_LENGTH);
	ip_header->ip_sum = checksum_received;
	return checksum_computed == checksum_received;
}

int icmpChecksumCorrect(struct IcmpHeader* icmp_header) {
	uint16_t checksum_received = icmp_header->icmp_sum;
   icmp_header->icmp_sum = 0;
   uint16_t checksum_computed = checksum(icmp_header, ICMP_HEADER_LENGTH);
   icmp_header->icmp_sum = checksum_received;
   return checksum_computed == checksum_received;
}

void handleIcmpPacket(struct Instance* sr, uint8_t* data, unsigned int len, char* interface) {
	/* Send echo reply to echo request */
	if (len < ICMP_PAYLOAD_OFFSET)
		return;
      
   struct IpHeader* ip_header = (struct IpHeader*)(data + ETHERNET_HEADER_LENGTH);
   struct IcmpHeader* icmp_header = (struct IcmpHeader*) (data + ICMP_OFFSET);
   if ( !icmpChecksumCorrect(icmp_header) )
  	   return;
      
   if (icmp_header->icmp_type == ICMP_TYPE_ECHO_REQ && icmp_header->icmp_code == ICMP_CODE_ECHO_REQ)
      /* echo doesn't need the original packet to be sent with the ICMP message, so pass null pointer (0) */
      sendIcmp(sr, ip_header->ip_src, ICMP_TYPE_ECHO_REPLY, ICMP_CODE_ECHO_REPLY, 0, interface);
}

void handleIpPacket(struct Instance* sr, uint8_t* frame_unformatted, unsigned int len, char* interface) {
  /* First do the length check. Unfortunately, I don't understand this part so I'm gonna skip it */
  if ( len < ETHERNET_HEADER_LENGTH + IP_HEADER_LENGTH ) {
    printf("*** Error: bad IP header length %d\n", len);
    return;
  }

  struct IpHeader* ip_header  = (struct IpHeader*)(frame_unformatted + ETHERNET_HEADER_LENGTH);
  if (!ipChecksumCorrect(ip_header))
  	return;
  
  struct Interface* target_interface = getInterfaceByIp(sr, ip_header->ip_dst);
  if (target_interface){
    /* the interface belongs to the router */
    if (ip_header->ip_p == ipProtocol_icmp) {
      handleIcmpPacket(sr, frame_unformatted, len, interface);
    }
    else {
    	/* If not an ICMP packet, must be TCP or UDP or something else. Probably client tracerouting us.
    	For unreachable messages, need to include original IP packet in ICMP message */
    	sendIcmp(sr, ip_header->ip_src, ICMP_TYPE_UNREACHABLE, ICMP_CODE_PORT_UNREACHABLE, frame_unformatted, interface);
    }
    return;
  }
  
  ip_header->ip_ttl--;
  if (ip_header->ip_ttl <= 0) {
  	/* Need to include original packet in this ICMP message */
    sendIcmp(sr, ip_header->ip_src, ICMP_TYPE_TTL_EXP, ICMP_CODE_TTL_EXP, frame_unformatted, interface);
    return;
  }
  ip_header->ip_sum = 0;
  ip_header->ip_sum = checksum(ip_header, IP_HEADER_LENGTH);
  
  /* don;t change this */
  sendIp(sr, ip_header->ip_dst, frame_unformatted, len, interface);
}

void handleArpPacket(struct Instance* sr, uint8_t* packet, unsigned int len, char* interface) {
  /* error if packet size is too small */
  if (len < ETHERNET_HEADER_LENGTH + ARP_HEADER_LENGTH){
    fprintf(stderr, "*** ARP Packet does not meet minimum length\n");
    return;
  }
  
  /* format arp header and get the request's target interface */
  struct ArpHeader* arp_header = (struct ArpHeader*) (packet + ETHERNET_HEADER_LENGTH);
  struct Interface* target_interface = getInterfaceByIp(sr, arp_header->ar_tip);
  
  if (target_interface) {
    printArpHeader((uint8_t*) arp_header);
    printInterface(target_interface);
    
    /* verify that the arp request is for our router's interface */
    if (strcmp(interface, target_interface->name) == 0) {
      unsigned short arp_code = ntohs(arp_header->ar_op);
      
      if (arp_code == arp_op_reply) {
        fprintf(stderr, "*** Handling ARP Reply\n");
        /* cache the response */
        struct ArpRequest* arp_request = arpCacheInsert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip);
        fprintf(stderr, "*** Cached ARP Entry\n");
        
        /* forward pending packets */
        struct RawFrame* pending_packet = arp_request ? arp_request->packets : NULL;
        for (; pending_packet != NULL; pending_packet = pending_packet->next)
          frameAndSendPacket(sr, pending_packet->buf, pending_packet->iface, pending_packet->len, arp_header->ar_sha, ethertype_ip);
      }
      else if (arp_code == arp_op_request) {
        fprintf(stderr, "*** Handling ARP Request\n");
        /* flip destination and target addresses */
        /* sender becomes target */
        memcpy(arp_header->ar_tha, arp_header->ar_sha, ETHERNET_ADDRESS_LENGTH);
        arp_header->ar_tip = arp_header->ar_sip;
        
        /* router interface becomes source */
        memcpy(arp_header->ar_sha, target_interface->addr, ETHERNET_ADDRESS_LENGTH);
        arp_header->ar_sip = target_interface->ip;
        
        /* flip arp request to reply */
        arp_header->ar_op = htons(arp_op_reply);
        
        /* update mac addresses */
        struct EthernetHeader* ethernet_header = (struct EthernetHeader*) packet;
        memcpy(ethernet_header->ether_dhost, arp_header->ar_tha, ETHERNET_ADDRESS_LENGTH);
        memcpy(ethernet_header->ether_shost, arp_header->ar_sha, ETHERNET_ADDRESS_LENGTH);
                        
        /* send packet */
        sendPacket(sr, packet, len, interface); 
        fprintf(stderr, "*** Sent ARP Reply\n");       
      }
      else {
        fprintf(stderr, "*** ARP Packet was neither an ARP Request nor ARP Reply\n");
        /* ARP was not a request or reply */
        /* return; */
      }
    }
    else {
      fprintf(stderr, "*** Target interface matches our IP but not name\n");
      /* packet interface and router interface names don't match */
      /* what should we do? */
    }
  }
  else {
    fprintf(stderr, "*** Target interface does not belong to our router\n");
  }
  /* return; */
}
