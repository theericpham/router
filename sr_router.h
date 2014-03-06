/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024
/*Caleb added:*/
#define IP_MIN_PACKET_SIZE 20
#define ETHERNET_MIN_FRAME_SIZE 64 /*14 header 46 payload 4 checksum*/
/*But why ... this seems to be wrong. Cus all the packets incoming say 42 bytes*/
/* forward declare */
struct Interface;
struct RoutingTable;

/* ----------------------------------------------------------------------------
 * struct Instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct Instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct Interface* if_list; /* list of interfaces */
    struct RoutingTable* routing_table; /* routing table */
    struct ArpCache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int verifyRoutingTable(struct Instance* sr);

/* -- sr_vns_comm.c -- */
int sendPacket(struct Instance* , uint8_t* , unsigned int , const char*);
int connectToServer(struct Instance* ,unsigned short , char* );
int readFromServer(struct Instance* );

/* -- sr_router.c -- */
void sr_init(struct Instance* );
void sr_handlepacket(struct Instance* , uint8_t * , unsigned int , char* );
/*Caleb and Eric's added functions */
void sr_handle_ip_packet(struct Instance* sr, uint8_t* packet, unsigned int len, char* interface);
void sr_handle_arp_packet(struct Instance* sr, uint8_t* packet, unsigned int len, char* interface);

/* -- sr_if.c -- */
void addInterface(struct Instance* , const char* );
void setEthernetIp(struct Instance* , uint32_t );
void setEthernetAddress(struct Instance* , const unsigned char* );
void printInterfaceList(struct Instance* );

#endif /* SR_ROUTER_H */
