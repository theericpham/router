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
int frameAndSendPacket(struct Instance* sr, uint8_t* packet, unsigned int len, unsigned char* mac, char* name) {
  /* get the interface to forward from */
  struct EthernetHeader* frame = (struct EthernetHeader*) packet;
  struct Interface* interface  = getInterface(sr, name);
  
  /* set MAC addresses */
  memcpy(frame->ether_dhost, mac, ETHERNET_ADDRESS_LENGTH);              /* dest specified by args */
  memcpy(frame->ether_shost, interface->addr, ETHERNET_ADDRESS_LENGTH);  /* src is interface MAC address */
    
  sendPacket(sr, packet, len, name);
  
  return 0;
}

/* 
 *  Send an ICMP message with type and code fields to dest from router interface 
 */
int sendIcmp(struct Instance* sr, uint32_t dest, uint8_t type, uint8_t code, char* interface) {
  int len           = ETHERNET_HEADER_LENGTH + IP_HEADER_LENGTH + ICMP_HEADER_LENGTH;
    
  /* construct headers */
  uint8_t* response_packet = (uint8_t*) malloc(len);
  struct IcmpHeader* icmp_hdr  = (struct IcmpHeader*) (response_packet + ICMP_OFFSET);
  struct IpHeader* ip_hdr      = (struct IpHeader*) (response_packet + ETHERNET_HEADER_LENGTH);
  struct EthernetHeader* ether_hdr = (struct EthernetHeader*) (response_packet);
  
  /* fill in icmp header */
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->icmp_sum  = 0;
  icmp_hdr->icmp_sum  = checksum(response_packet + ICMP_OFFSET, ICMP_HEADER_LENGTH);
  
  /* fill in ip header */
  ip_hdr->ip_v   = IP_VERSION_4;
  ip_hdr->ip_hl  = IP_HEADER_LEN;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_len = IP_HEADER_LENGTH + ICMP_HEADER_LENGTH;
  ip_hdr->ip_id  = 0;
  ip_hdr->ip_off = IP_DF;
  ip_hdr->ip_ttl = IP_DEFAULT_TTL;
  ip_hdr->ip_p   = ipProtocol_icmp;
  
  /* get the outgoing interface and set ip src and dst */
  struct Interface* src_if = getInterface(sr, interface);
  ip_hdr->ip_dst = dest;
  ip_hdr->ip_src = src_if->ip;
  
  /* compute ip header checksum */
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = checksum(response_packet + ETHERNET_HEADER_LENGTH, IP_HEADER_LENGTH);
  
  /* set ethernet header ethertype */
  ether_hdr->ether_type = ethertype_ip;
  
  /* find route to dest */
  struct RoutingTable* route = findLpmRoute(sr, dest);
  if (route == NULL) {
    /* TODO print error or send ICMP? */
    return -1;
  }
  
  /* find ARP entry for MAC */
  struct ArpEntry* arp_entry = arpCacheLookup(&(sr->cache), dest);
  if (arp_entry) {
    /* TODO fill in ethernet header and set if entry exists */
    /* FIXED the following function call fills in ethernet header and sends packet 
     *       frameAndSendPacket defined above on line 47
     */
    frameAndSendPacket(sr, response_packet, len, arp_entry->mac, route->interface);
    free(arp_entry);
  }
  else {
    /* queue and handle arp request if no entry exists */
    struct ArpRequest* arp_req = arpCacheQueueRequest(&(sr->cache), dest, response_packet, len, route->interface);
    arp_req->interface = route->interface;
    /* TODO  what is router ? */
    /* I think this should be route->interface (not router).  Your thoughts? */
    handleArpRequest(sr, arp_req);
  }
  
  return 0;
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
  struct IpHeader* ip_header  = (struct IpHeader*)frame_unformatted;
  /* Make sure the checksum is OK */
  uint16_t checksum_received = ip_header->ip_sum;
  uint16_t checksum_computed = checksum(ip_header, sizeof(struct IpHeader));
  if ( checksum_received != checksum_computed )
  	printf("*** Checksum doesn't match :(");
  	/* TODO I think this logic is wrong */
  
  
}

void handleArpPacket(struct Instance* sr, uint8_t* packet, unsigned int len, char* interface) {}
