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

#define ARP_REQUEST_SEND_INTERVAL       1.0
#define ARP_REQUEST_SEND_LIMIT          5

#define ICMP_TYPE_UNREACHABLE       3
#define ICMP_CODE_HOST              1

#define IP_ADDRESS_LENGTH                 4

int frameAndSendPacket(struct Instance* sr, uint8_t* packet, unsigned int len, unsigned char* mac, char* name);
int sendIcmp(struct Instance* sr, uint32_t dest, uint8_t type, uint8_t code, char* interface);

int handleArpRequest(struct Instance* sr, struct ArpRequest* req) {
  printf("*** Processing ARP Request ***\n");
  
  time_t now = time(NULL);
  IpHeader_t* ip_hdr;
  int ethernet_hdr_offset = sizeof(EthernetHeader_t);
  
  if (difftime(now, req->sent) > ARP_REQUEST_SEND_INTERVAL) {
    if (req->times_sent >= ARP_REQUEST_SEND_LIMIT) {
      struct RawFrame* packet;
      for (packet = req->packets; packet != NULL; packet = packet->next) {
        /* TODO: Fix this. What is packet->iface, and why does line 37 say incompat ptr type? */
        /* Resolved incompat ptr type by removing 'struct' from ptr declaration */
        ip_hdr = (IpHeader_t*) (packet + ethernet_hdr_offset);
        if (sendIcmp(sr, ip_hdr->ip_src, ICMP_TYPE_UNREACHABLE, ICMP_CODE_HOST, packet->iface) < 0)
          ;/* print error message */
      }
      destroyArpRequest(&(sr->cache), req);
    }
  }
  else {
    int ether_hdr_len  = sizeof(EthernetHeader_t);
    int arp_hdr_len    = sizeof(ArpHeader_t);
    int arp_hdr_offset = ether_hdr_len;
    int len            = ether_hdr_len + arp_hdr_len;
    
    /* create headers */
    uint8_t* response = (uint8_t*) malloc(len);
    EthernetHeader_t* ether_hdr = (EthernetHeader_t*) req; /*Fixed: was response*/
    ArpHeader_t* arp_hdr        = (ArpHeader_t*) (ether_hdr + arp_hdr_offset);
    
    /* get interface */
    struct Interface* interface = getInterface(sr, req->interface);
    
    ether_hdr->ether_type = ethertype_arp;
    
    /* fill in arp header */
    arp_hdr->ar_hrd = arp_hardware_ethernet;
    arp_hdr->ar_pro = ethertype_ip;
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = IP_ADDRESS_LENGTH;
    arp_hdr->ar_op  = arp_op_request;
    arp_hdr->ar_sip = interface->ip;
    arp_hdr->ar_tip = req->ip;
    
    /* set source and destination info */
    memcpy(arp_hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
    memcpy(ether_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
    
    int i;
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
      arp_hdr->ar_tha[i] = 0xFF;
      ether_hdr->ether_dhost[i] = 0xFF;
    }
    
    /* send packet */
    sendPacket(sr, response, len, interface->name);
    
    /* update request info */
    req->sent = time(NULL);
    req->times_sent = req->times_sent + 1;
  }
  
  return 0;
}

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void arpCacheSweepRequests(struct Instance *sr) { 
  assert(sr);
  struct ArpRequest* req = sr->cache.requests;
  int err;
  for (; req != NULL; req = req->next){
    if ((err = handleArpRequest(sr, req)) < 0)
      printf("*** Error %i Handling ARP Request\n", err);
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

