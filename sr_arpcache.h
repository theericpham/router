/* This file defines an ARP cache, which is made of two structures: an ARP
   request queue, and ARP cache entries. The ARP request queue holds data about
   an outgoing ARP cache request and the packets that are waiting on a reply
   to that ARP cache request. The ARP cache entries hold IP->MAC mappings and
   are timed out every SR_ARPCACHE_TO seconds.

   Pseudocode for use of these structures follows.

   --

   # When sending packet to next_hop_ip
   entry = arpCache_lookup(next_hop_ip)

   if entry:
       use next_hop_ip->mac mapping in entry to send the packet
       free entry
   else:
       req = arpCache_queuereq(next_hop_ip, packet, len)
       handle_arpreq(req)

   --

   The handle_arpreq() function is a function you should write, and it should
   handle sending ARP requests if necessary:

   function handle_arpreq(req):
       if difftime(now, req->sent) > 1.0
           if req->times_sent >= 5:
               send icmp host unreachable to source addr of all pkts waiting
                 on this request
               arpreq_destroy(req)
           else:
               send arp request
               req->sent = now
               req->times_sent++

   --

   The ARP reply processing code should move entries from the ARP request
   queue to the ARP cache:

   # When servicing an arp reply that gives us an IP->MAC mapping
   req = arpCache_insert(ip, mac)

   if req:
       send all packets on the req->packets linked list
       arpreq_destroy(req)

   --

   To meet the guidelines in the assignment (ARP requests are sent every second
   until we send 5 ARP requests, then we send ICMP host unreachable back to
   all packets waiting on this ARP request), you must fill out the following
   function that is called every second and is defined in sr_arpCache.c:

   void arpCacheSweepRequests(struct Instance *sr) {
       for each request on sr->cache.requests:
           handle_arpreq(request)
   }

   Since handle_arpreq as defined in the comments above could destroy your
   current request, make sure to save the next pointer before calling
   handle_arpreq when traversing through the ARP requests linked list.
 */

#ifndef SR_ARPCACHE_H
#define SR_ARPCACHE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include "sr_if.h"

#define ARPCACHE_SIZE            100  
#define SR_ARPCACHE_TO            15.0
#define SR_ARPCACHE_MAX_SENDS     5
#define SR_ARPCACHE_SEND_INTERVAL 1.0

struct RawFrame {
    uint8_t *buf;               /* A raw Ethernet frame, presumably with the dest MAC empty */
    unsigned int len;           /* Length of raw Ethernet frame */
    char *iface;                /* The outgoing interface */
    struct RawFrame *next;
};

struct ArpEntry {
    unsigned char mac[6]; 
    uint32_t ip;                /* IP addr in network byte order */
    time_t added;         
    int valid;
};

struct ArpRequest {
    uint32_t ip;
    time_t sent;                /* Last time this ARP request was sent. You 
                                   should update this. If the ARP request was 
                                   never sent, will be 0. */
    uint32_t times_sent;        /* Number of times this request was sent. You 
                                   should update this. */
    struct RawFrame *packets;  /* List of pkts waiting on this req to finish */
    struct ArpRequest *next;
    char* interface; /* Fixed: added this. let's see if it works */
};

struct ArpCache {
    struct ArpEntry entries[ARPCACHE_SIZE];
    struct ArpRequest *requests;
    pthread_mutex_t lock;
    pthread_mutexattr_t attr;
};

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order. 
   You must free the returned structure if it is not NULL. */
struct ArpEntry* arpCacheLookup(struct ArpCache *cache, uint32_t ip);

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this ArpRequest
   that corresponds to this ARP request. The packet argument should not be
   freed by the caller.

   A pointer to the ARP request is returned; it should be freed. The caller
   can remove the ARP request from the queue by calling destroyArpRequest. */
struct ArpRequest* arpCacheQueueRequest(struct ArpCache *cache,
                         uint32_t ip,
                         uint8_t *packet,               /* borrowed */
                         unsigned int packet_len,
                         char *iface);

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the ArpRequest with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct ArpRequest *arpCacheInsert(struct ArpCache *cache,
                                     unsigned char *mac,
                                     uint32_t ip);

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void destroyArpRequest(struct ArpCache *cache, struct ArpRequest *entry);

/* Prints out the ARP table. */
void arpCacheDump(struct ArpCache *cache);

/* You shouldn't have to call these methods--they're already called in the
   starter code for you. The init call is a constructor, the destroy call is
   a destructor, and a cleanup thread times out cache entries every 15
   seconds. */

int   arpCacheInit(struct ArpCache *cache);
int   arpCacheDestroy(struct ArpCache *cache);
void *arpCacheTimeout(void *cache_ptr);

/* Handles and sends ARP requests waiting in the queue. */
int handleArpRequest(struct Instance* sr, struct ArpRequest* req);

#endif
