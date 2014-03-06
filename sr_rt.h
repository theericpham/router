/*-----------------------------------------------------------------------------
 * file:  sr_rt.h 
 * date:  Mon Oct 07 03:53:53 PDT 2002  
 * Author: casado@stanford.edu
 *
 * Description:
 *
 * Methods and datastructures for handeling the routing table
 *
 *---------------------------------------------------------------------------*/

#ifndef sr_RT_H
#define sr_RT_H

#ifdef _DARWIN_
#include <sys/types.h>
#endif

#include <netinet/in.h>

#include "sr_if.h"

/* ----------------------------------------------------------------------------
 * struct RoutingTable
 *
 * Node in the routing table 
 *
 * -------------------------------------------------------------------------- */

struct RoutingTable
{
    struct in_addr dest;
    struct in_addr gw;
    struct in_addr mask;
    char   interface[sr_IFACE_NAMELEN];
    struct RoutingTable* next;
};


int loadRoutingTable(struct Instance*,const char*);
void addRoutingTableEntry(struct Instance*, struct in_addr,struct in_addr,
                  struct in_addr, char*);
void printRoutingTable(struct Instance* sr);
void printRoutingEntry(struct RoutingTable* entry);

/* return longest prefix match for dest in routing table if one exists */
struct RoutingTable* findLpmRoute(struct Instance* sr, uint32_t dest);
#endif  /* --  sr_RT_H -- */
