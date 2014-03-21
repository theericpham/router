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

struct RawFrame { /* Previously sr_packet */
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

int frameAndSendPacket(struct Instance*, uint8_t*, char*, unsigned int, unsigned char*, enum Ethertype);

#endif
