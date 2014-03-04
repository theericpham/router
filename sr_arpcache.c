#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"

#define ARP_REQ_SEND_INTERVAL       1.0
#define ARP_REQ_SEND_LIMIT          5
#define ICMP_TYPE_ECHO_REPLY        0
#define ICMP_CODE_ECHO_REPLY        0
#define ICMP_TYPE_DEST_UNREACHABLE  3
#define ICMP_CODE_NET_UNREACHABLE   0
#define ICMP_CODE_PORT_UNREACHABLE  3
#define ICMP_CODE_HOST_UNREACHABLE  1
#define ICMP_TYPE_TIME_EXCEEDED     11
#define ICMP_CODE_TTL_EXPIRED       0
#define IP_V4                       4
#define IP_HEADER_LEN               5
#define IP_HEADER_TTL               16


/*
  Send an ICMP message with the type, code, and payload specified by function arguments
*/
int sr_send_msg(struct sr_instance* sr, uint8_t type, uint8_t code, uint32_t dest, char* interface) {
  printf("*** Initializing ICMP Packet with Type %i: Code %i\n", type, code);
  
  // mark the start offset of the icmp message
  // set the full length of the ethernet frame
  int eth_hdr_size  = sizeof(sr_ethernet_hdr_t);
  int ip_hdr_size   = sizeof(sr_ip_hdr_t);
  int icmp_hdr_size = sizeof(sr_icmp_hdr_t);
  int ip_offset     = eth_hdr_size;
  int icmp_offset   = eth_hdr_size + ip_hdr_size;
  int len           = eth_hdr_size + ip_hdr_size + icmp_hdr_size;
  
  // allocate mem for ethernet frame
  uint8_t* eth_frame = (uint8_t*) malloc(len);
  
  // fill in icmp header
  sr_icmp_hdr_t* msg = (sr_icmp_hdr_t*) (eth_frame + icmp_offset);
  msg->icmp_type = type;
  msg->icmp_code = code;
  msg->sum       = 0;
  msg->sum       = cksum(ether_frame + icmp_offset, icmp_hdr_size));
  
  printf("*** Created ICMP Header with Message ***\n");
  
  // fill in ip header
  sr_ip_hdr_t* packet  = (sr_ip_hdr_t*) (eth_frame + ip_offset);
  packet->ip_v   = IP_V4;
  packet->ip_hl  = IP_HEADER_LEN;
  packet->ip_tos = 0;
  packet->ip_len = htons(len - ip_offset);
  packet->ip_id  = htons(0);
  packet->ip_off = htons(IP_DF);
  packet->ip_dst = dip;
  packet->ip_src = source->ip;  
  packet->ip_ttl = IP_HEADER_TTL;
  packet->ip_p   = ip_protocol_icmp;
  
  // set source and destination ip
  struct sr_if* source = sr_get_interface(sr, interface);
  packet->ip_dst = dest;
  packet->ip_src = source->ip;
  
  // compute ip checksum
  packet->ip_sum = 0;
  packet->ip_sum = cksum(eth_frame + ip_offset, ip_hdr_size);
  
  printf("*** Created IP Packet ***\n");
  
  // create ethernet frame
  sr_ethernet_hdr_t* frame = (sr_ethernet_hdr_t*) (eth_frame);
  frame->ether_type = htons(ethertype_ip);
  
  printf("*** Created Ethernet Frame ***\n");
  
  
  free(eth_frame);
  
  return 0;
}


int sr_handle_arp_req(struct sr_instance* sr, struct sr_arpreq* req) {
  printf("*** Processing ARP Request ***\n");
  
  time_t now = time(NULL);
  if (difftime(now, req->sent) > ARP_REQ_SEND_INTERVAL) {
    printf("*** ARP Request has been sent %i times ***\n", req->times_sent)
    if (req->times_sent >= ARP_REQ_SEND_LIMIT) {
      printf("*** ARP Request has reached send limit ***\n")
      
      // send ICMP host unreachable to source of
      // each packet pending on ARP request
      struct sr_packet* packet;
      for (packet = req->packets; packet != NULL; packet = packet->next) {
        // send ICMP packet
      }
    }
    else {
      // send ARP request
      
      
      // update ARP request info
      req->sent = now;
      req->times_sent = req->times_sent + 1;
    }
  }
  
  return 0;
}

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
  assert(sr);
  struct sr_arpreq* req = sr->cache.requests;
  for (; req != NULL; req = req->next){
    if (int err = sr_handle_arp_request(sr, req) < 0)
      printf("*** Error %i Handling ARP Request\n", err);
  } 
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
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
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
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
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
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
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
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
        
        struct sr_packet *pkt, *nxt;
        
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
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
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
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

