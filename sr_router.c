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

/*---------------------------------------------------------------------
 * Declaration of Helper Functions
 *
 *---------------------------------------------------------------------*/

int sendIcmp(struct Instance* sr, uint32_t dest, uint8_t type, uint8_t code, char* interface); /*Fixed*/
int frameAndSendPacket(struct Instance* sr, uint8_t* packet, unsigned int len, unsigned char* mac, char* iface);

/* 
 *  Set ethernet frame for a packet by filling in MAC addresses and send the packet 
 */
int frameAndSendPacket(struct Instance* sr, uint8_t* packet, unsigned int length, unsigned char* mac, char* interface_name) {
  /* get the interface to forward from */
  struct EthernetHeader* frame = (struct EthernetHeader*) packet;
  struct Interface* interface  = getInterface(sr, interface_name);
  
  /* set MAC addresses */
  memcpy(frame->ether_dhost, mac, ETHERNET_ADDRESS_LENGTH);              /* dest specified by args */
  memcpy(frame->ether_shost, interface->addr, ETHERNET_ADDRESS_LENGTH);  /* src is interface MAC address */
    
  sendPacket(sr, packet, length, interface_name);
  
  return 0;
}

int sendIp(struct Instance* sr, uint32_t destination_ip, uint8_t* data, int length, char* interface) {
	/* First get a pointer to the IP header of this data */
	struct IpHeader* ip_header = (struct IpHeader*)(data + ETHERNET_HEADER_LENGTH);
	/* Generic IP header information */
	ip_header->ip_v   = IP_VERSION_4;
	ip_header->ip_hl  = IP_HEADER_LEN;
	ip_header->ip_tos = 0;
	ip_header->ip_len = IP_HEADER_LENGTH + ICMP_HEADER_LENGTH;
	ip_header->ip_id  = 0;
	ip_header->ip_off = IP_DF;
	ip_header->ip_ttl = IP_DEFAULT_TTL;
	ip_header->ip_p   = ipProtocol_icmp;
	/* Specific things for this packet */
	struct Interface* source_interface = getInterface(sr, interface);
	ip_header->ip_dst = destination_ip;
	ip_header->ip_src = source_interface->ip;
	/* compute ip header checksum */
	ip_header->ip_sum = checksum(data + ETHERNET_HEADER_LENGTH, IP_HEADER_LENGTH);
	
	/* Next look up the route to the destination IP */
	struct RoutingTable* route = findLpmRoute(sr, destination_ip);
	if (!route)
		return -1; /* TODO print error or send ICMP? */
	/* The only thing we'll be using from this route is which one of our interfaces it uses. */
	char* sending_interface = route->interface;
	
	/* Now see if the address for this destination is in our ARP cache */
	struct ArpEntry* arp_entry = arpCacheLookup(&(sr->cache), destination_ip);
	if (arp_entry) {
		frameAndSendPacket(sr, data, length, arp_entry->mac, sending_interface);
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
int sendIcmp(struct Instance* sr, uint32_t destination_ip, uint8_t type, uint8_t code, char* interface) {
	/* construct headers */
	int length = ETHERNET_HEADER_LENGTH + IP_HEADER_LENGTH + ICMP_HEADER_LENGTH;
	uint8_t* response_packet = (uint8_t*) malloc(length);
	struct IcmpHeader* icmp_header  = (struct IcmpHeader*) (response_packet + ICMP_OFFSET);

	/* fill in icmp header */
	icmp_header->icmp_type = type;
	icmp_header->icmp_code = code;
	icmp_header->icmp_sum  = checksum(response_packet + ICMP_OFFSET, ICMP_HEADER_LENGTH);

	/* Pass the packet to sendIp, which will take care of the IP header formatting and look up the destination in the ARP cache
	Return whatever status this function returns. */
  
	return sendIp(sr, destination_ip, response_packet, length, interface);
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

  /*First need to figure out what protocol is running above Ethernet here.*/
  short ether_type = ethertype(packet);
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

void handleIpPacket(struct Instance* sr, uint8_t* frame_unformatted, unsigned int len, char* interface) {
  /* First do the length check. Unfortunately, I don't understand this part so I'm gonna skip it */
  if ( 0 )
    printf("*** Error: bad IP header length %d\n", len);
    /* Should we also send an ICMP type 12 code 2 bad header length? */
  
  /*Need to encapsulate the frame into an IP header object*/
  struct IpHeader* ip_header  = (struct IpHeader*)(frame_unformatted + ETHERNET_HEADER_LENGTH);
  /* Make sure the checksum is OK */
  uint16_t checksum_received = ip_header->ip_sum;
  ip_header->ip_sum = 0;
  uint16_t checksum_computed = checksum(ip_header, IP_HEADER_LENGTH);
  printIpHeader((uint8_t*)ip_header);
  if ( checksum_received != checksum_computed )
  	printf("*** Checksum doesn't match :(");
  
  
}

void handleArpPacket(struct Instance* sr, uint8_t* packet, unsigned int len, char* interface) {
  /* error if packet size is too small */
  if (len < ETHERNET_HEADER_LENGTH + ARP_HEADER_LENGTH)
    return -1;
  
  /* format arp header and get the request's target interface */
  struct ArpHeader* arp_header = (struct ArpHeader*) (packet + ETHERNET_HEADER_LENGTH);
  struct Interface* target_interface = getInterface(sr, arp_header->arp_tip);
  
  if (target_interface) {
    /* debug statement */
    sr_print_if(target_interface);
    
    /* verify that the arp request is for our router's interface */
    if (strcmp(interface, target_interface->name) == 0) {
      unsigned short arp_code = arp_header->ar_op;
      
      if (arp_code == arp_op_reply) {
        /* cache the response */
        struct ArpRequest* arp_request = arpCacheInsert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip);
        
        /* forward pending packets */
        struct RawFrame* pending_packet = arp_request ? arp_request->packets : NULL;
        for (; pending_packet != NULL; pending_packet = pending_packet->next)
          frameAndSendPacket(sr, pending_packet->buf, pending_packet->len, arp_header->ar_sha, pending_packet->iface);
      }
      else if (arp_code == arp_op_request) {
        /* flip destination and target addresses */
        /* sender becomes target */
        memcpy(arp_header->ar_tha, arp_header->ar_sha, ETHERNET_ADDRESS_LENGTH);
        arp_header->ar_tip = arp_header->ar_sip;
        
        /* router interface becomes source */
        memcpy(arp_header->ar_sha, interface->addr, ETHERNET_ADDRESS_LENGTH);
        arp_header->ar_tip = interface->ip;
        
        /* flip arp request to reply */
        arp_header->ar_op = arp_op_reply;
        
        /* update mac addresses */
        EthernetHeader* ethernet_header = (EthernetHeader*) packet;
        memcpy(ethernet_header->ether_dhost, arp_header->ar_tha, ETHERNET_ADDRESS_LENGTH);
        memcpy(ethernet_header->ether_shost, arp_header->ar_sha, ETHERNET_ADDRESS_LENGTH);
        
        /* send packet */
        sendPacket(sr, packet, len, interface);        
      }
      else {
        /* ARP was not a request or reply */
        return -1;
      }
    }
    else {
      /* packet interface and router interface names don't match */
      /* what should we do? */
    }
  }
  
  return 0;
}
