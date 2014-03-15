/*-----------------------------------------------------------------------------
 * file:  sr_rt.c
 * date:  Mon Oct 07 04:02:12 PDT 2002
 * Author:  casado@stanford.edu
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>


#include <sys/socket.h>
#include <netinet/in.h>
#define __USE_MISC 1 /* force linux to show inet_aton */
#include <arpa/inet.h>

#include "sr_rt.h"
#include "sr_router.h"
#include "sr_utils.h"	

#define ERR_NULL_ROUTING_TABLE -1

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

int loadRoutingTable(struct Instance* sr,const char* filename)
{
    FILE* fp;
    char  line[BUFSIZ];
    char  dest[32];
    char  gw[32];
    char  mask[32];
    char  iface[32];
    struct in_addr dest_addr;
    struct in_addr gw_addr;
    struct in_addr mask_addr;
    int clear_routing_table = 0;

    /* -- REQUIRES -- */
    assert(filename);
    if( access(filename,R_OK) != 0)
    {
        perror("access");
        return -1;
    }

    fp = fopen(filename,"r");

    while( fgets(line,BUFSIZ,fp) != 0)
    {
        sscanf(line,"%s %s %s %s",dest,gw,mask,iface);
        if(inet_aton(dest,&dest_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    dest);
            return -1; 
        }
        if(inet_aton(gw,&gw_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    gw);
            return -1; 
        }
        if(inet_aton(mask,&mask_addr) == 0)
        { 
            fprintf(stderr,
                    "Error loading routing table, cannot convert %s to valid IP\n",
                    mask);
            return -1; 
        }
        if( clear_routing_table == 0 ){
            printf("Loading routing table from server, clear local routing table.\n");
            sr->routing_table = 0;
            clear_routing_table = 1;
        }
        addRoutingTableEntry(sr,dest_addr,gw_addr,mask_addr,iface);
    } /* -- while -- */

    return 0; /* -- success -- */
} /* -- loadRoutingTable -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void addRoutingTableEntry(struct Instance* sr, struct in_addr dest,
struct in_addr gw, struct in_addr mask,char* if_name)
{
    struct RoutingTable* rt_walker = 0;

    /* -- REQUIRES -- */
    assert(if_name);
    assert(sr);

    /* -- empty list special case -- */
    if(sr->routing_table == 0)
    {
        sr->routing_table = (struct RoutingTable*)malloc(sizeof(struct RoutingTable));
        assert(sr->routing_table);
        sr->routing_table->next = 0;
        sr->routing_table->dest = dest;
        sr->routing_table->gw   = gw;
        sr->routing_table->mask = mask;
        strncpy(sr->routing_table->interface,if_name,sr_IFACE_NAMELEN);

        return;
    }

    /* -- find the end of the list -- */
    rt_walker = sr->routing_table;
    while(rt_walker->next){
      rt_walker = rt_walker->next; 
    }

    rt_walker->next = (struct RoutingTable*)malloc(sizeof(struct RoutingTable));
    assert(rt_walker->next);
    rt_walker = rt_walker->next;

    rt_walker->next = 0;
    rt_walker->dest = dest;
    rt_walker->gw   = gw;
    rt_walker->mask = mask;
    strncpy(rt_walker->interface,if_name,sr_IFACE_NAMELEN);

} /* -- sr_add_entry -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void printRoutingTable(struct Instance* sr)
{
    struct RoutingTable* rt_walker = 0;

    if(sr->routing_table == 0)
    {
        printf(" *warning* Routing table empty \n");
        return;
    }

    printf("Destination\tGateway\t\tMask\tIface\n");

    rt_walker = sr->routing_table;
    
    printRoutingEntry(rt_walker);
    while(rt_walker->next)
    {
        rt_walker = rt_walker->next; 
        printRoutingEntry(rt_walker);
    }

} /* -- printRoutingTable -- */

/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/

void printRoutingEntry(struct RoutingTable* entry)
{
    /* -- REQUIRES --*/
    assert(entry);
    assert(entry->interface);

    printf("%s\t\t",inet_ntoa(entry->dest));
    printf("%s\t",inet_ntoa(entry->gw));
    printf("%s\t",inet_ntoa(entry->mask));
    printf("%s\n",entry->interface);

} /* -- printRoutingEntry -- */

/* return longest prefix match route if any */
struct RoutingTable* findLpmRoute(struct Instance* sr, uint32_t dest) {
  uint32_t len = 0;
  struct RoutingTable* result = 0;
  struct RoutingTable* iter;
  
  for(iter = sr->routing_table; iter != 0; iter = iter->next) { /*Fixed: replaced cur with iter*/
  /*Fixed: (iter->mask).s_addr should be iter->mask.s_addr */
    fprintf(stderr, "Comparing "); printIpAddress_int(dest & ntohl(iter->mask.s_addr));
    fprintf(stderr, " with "); printIpAddress_int(ntohl(iter->dest.s_addr & iter->mask.s_addr)); fprintf(stderr, "\n");
    fprintf(stderr, "Comparing length of "); printIpAddress_int(len); fprintf(stderr, " with "); printIpAddress_int(ntohl(iter->mask.s_addr)); fprintf(stderr, "\n");
    if (((dest & ntohl(iter->mask.s_addr)) == ntohl(iter->dest.s_addr & iter->mask.s_addr)) &&
      (len <= ntohl(iter->mask.s_addr))) {
        result = iter;
        len = ntohl(iter->mask.s_addr);
    }
  }
  
  fprintf(stderr, "*** Printing Routing Table\n");
  printRoutingTable(sr);
  
  if (result) {
    fprintf(stderr, "*** Found Longest Prefix Match:\n");
    printRoutingEntry(result);    
  } else {
    fprintf(stderr, "*** No Routing Entry Found for Address %i\n", dest);
  }
  return result;
}
