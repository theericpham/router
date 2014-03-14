#define SKIP_ARP_SWEEP 0	/* Turn off periodic sweep for debugging */

#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <assert.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

#define ARP_REQUEST_SEND_INTERVAL 1.0
#define ARP_REQUEST_SEND_LIMIT    5

#define ICMP_TYPE_UNREACHABLE     3
#define ICMP_CODE_HOST            1

#define IP_ADDRESS_LENGTH         4

unsigned char BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

int sendIcmp(struct Instance* sr, uint32_t dest, uint8_t type, uint8_t code, char* interface);

int handleArpRequest(struct Instance* sr, struct ArpRequest* request) {  
  time_t now = time(NULL);
  struct IpHeader* ip_hdr;
  if (difftime(now, request->sent) < ARP_REQUEST_SEND_INTERVAL) {
    fprintf(stderr, "*** Not enough time has elapsed between last send of this ARP Request\n");
    return -1;
  }
    
  fprintf(stderr, "*** It's been a while since we last sent this ARP Request\n");
  if (request->times_sent >= ARP_REQUEST_SEND_LIMIT) {
    fprintf(stderr, "*** ARP Request has reached send limit\n");
    fprintf(stderr, "*** Preparing to send ICMP for ARP Request\n");
    struct RawFrame* packet;
    for (packet = request->packets; packet != NULL; packet = packet->next) {
      ip_hdr = (struct IpHeader*) (packet->buf + ETHERNET_HEADER_LENGTH);
      fprintf(stderr, "*** Parsed IP Packet Waiting on this ARP Request:\n");
      printIpHeader((uint8_t*) ip_hdr);
      if (sendIcmp(sr, ip_hdr->ip_src, ICMP_TYPE_UNREACHABLE, ICMP_CODE_HOST, packet->iface) < 0)
        fprintf(stderr, "*** Unable to send ICMP\n");/* print error message */
    }
    destroyArpRequest(&(sr->cache), request);
  }
  else {
    fprintf(stderr, "*** Preparing to re-send ARP Request\n");
    int length = ETHERNET_HEADER_LENGTH + ARP_HEADER_LENGTH;
  
    /* create headers */
    uint8_t* response = (uint8_t*) malloc(length);
    struct ArpHeader* arp_header = (struct ArpHeader*) (response + ETHERNET_HEADER_LENGTH);
  
    /* Get the details of the interface the ARP request wants us to send from */
    struct Interface* interface = getInterface(sr, request->interface);
    if (interface) {
      fprintf(stderr, "*** Found Interface %s\n", interface->name);
      printInterface(interface);
    }
    else {
      fprintf(stderr, "*** No Interface Found for ARP Request\n");
    }
  
    /* fill in arp header */
    arp_header->ar_hrd = htons(arp_hardware_ethernet);
    arp_header->ar_pro = htons(ethertype_ip);
    arp_header->ar_hln = ETHERNET_ADDRESS_LENGTH;
    arp_header->ar_pln = IP_ADDRESS_LENGTH;
    arp_header->ar_op  = htons(arp_op_request);
    arp_header->ar_sip = interface->ip;
    arp_header->ar_tip = request->ip;
    memcpy(arp_header->ar_sha, interface->addr, ETHERNET_ADDRESS_LENGTH);
    fprintf(stderr, "*** Formed ARP Request Header\n");
  
    /* move to frameAndSend */
    /*memcpy(ether_hdr->ether_shost, interface->addr, ETHERNET_ADDRESS_LENGTH);
	  ether_hdr->ether_dhost[i] = 0xFF; */

    memcpy(arp_header->ar_tha, BROADCAST_MAC, ETHERNET_ADDRESS_LENGTH);
    
    /* debug statement */
    printArpHeader((uint8_t*) arp_header);
  
    /* previously  sendPacket(sr, response, len, interface->name);*/
    /* TODO: request->interface is NULL */
    frameAndSendPacket(sr, response, request->interface, length, BROADCAST_MAC, ethertype_arp);
  
    /* update request info */
    request->sent = time(NULL);
    request->times_sent++;
    fprintf(stderr, "*** ARP Request has been re-sent\n");
  }
  return 0;
}

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void arpCacheSweepRequests(struct Instance *sr) { 
  if (SKIP_ARP_SWEEP)
    return;  
  assert(sr);
  struct ArpRequest* req = sr->cache.requests;
  int err;
  for (; req != NULL; req = req->next){
    if ((err = handleArpRequest(sr, req)) < 0)
      fprintf(stderr, "*** Error %i Handling ARP Request\n", err);
  } 
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct ArpEntry *arpCacheLookup(struct ArpCache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct ArpEntry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < ARPCACHE_SIZE; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct ArpEntry *) malloc(sizeof(struct ArpEntry));
        memcpy(copy, entry, sizeof(struct ArpEntry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this ArpRequest
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling destroyArpRequest. */
struct ArpRequest *arpCacheQueueRequest(struct ArpCache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct ArpRequest *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct ArpRequest *) calloc(1, sizeof(struct ArpRequest));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct RawFrame *new_pkt = (struct RawFrame *)malloc(sizeof(struct RawFrame));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the ArpRequest with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct ArpRequest *arpCacheInsert(struct ArpCache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct ArpRequest *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < ARPCACHE_SIZE; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != ARPCACHE_SIZE) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void destroyArpRequest(struct ArpCache *cache, struct ArpRequest *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct ArpRequest *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct RawFrame *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void arpCacheDump(struct ArpCache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < ARPCACHE_SIZE; i++) {
        struct ArpEntry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int arpCacheInit(struct ArpCache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int arpCacheDestroy(struct ArpCache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *arpCacheTimeout(void *sr_ptr) {
    struct Instance *sr = sr_ptr;
    struct ArpCache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < ARPCACHE_SIZE; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        arpCacheSweepRequests(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

