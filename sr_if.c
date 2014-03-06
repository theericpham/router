/*-----------------------------------------------------------------------------
 * file:  sr_inface.
 * date:  Sun Oct 06 14:13:13 PDT 2002 
 * Contact: casado@stanford.edu 
 *
 * Description:
 *
 * Data structures and methods for handling interfaces
 *
 *---------------------------------------------------------------------------*/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#ifdef _DARWIN_
#include <sys/types.h>
#endif /* _DARWIN_ */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sr_if.h"
#include "sr_router.h"

/*--------------------------------------------------------------------- 
 * Method: getInterface
 * Scope: Global
 *
 * Given an interface name return the interface record or 0 if it doesn't
 * exist.
 *
 *---------------------------------------------------------------------*/

struct sr_if* getInterface(struct sr_instance* sr, const char* name)
{
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    assert(name);
    assert(sr);

    if_walker = sr->if_list;

    while(if_walker)
    {
       if(!strncmp(if_walker->name,name,sr_IFACE_NAMELEN))
        { return if_walker; }
        if_walker = if_walker->next;
    }

    return 0;
} /* -- getInterface -- */

/*--------------------------------------------------------------------- 
 * Method: addInterface(..)
 * Scope: Global
 *
 * Add and interface to the router's list
 *
 *---------------------------------------------------------------------*/

void addInterface(struct sr_instance* sr, const char* name)
{
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    assert(name);
    assert(sr);

    /* -- empty list special case -- */
    if(sr->if_list == 0)
    {
        sr->if_list = (struct sr_if*)malloc(sizeof(struct sr_if));
        assert(sr->if_list);
        sr->if_list->next = 0;
        strncpy(sr->if_list->name,name,sr_IFACE_NAMELEN);
        return;
    }

    /* -- find the end of the list -- */
    if_walker = sr->if_list;
    while(if_walker->next)
    {if_walker = if_walker->next; }

    if_walker->next = (struct sr_if*)malloc(sizeof(struct sr_if));
    assert(if_walker->next);
    if_walker = if_walker->next;
    strncpy(if_walker->name,name,sr_IFACE_NAMELEN);
    if_walker->next = 0;
} /* -- addInterface -- */ 

/*--------------------------------------------------------------------- 
 * Method: sr_sat_ether_addr(..)
 * Scope: Global
 *
 * set the ethernet address of the LAST interface in the interface list
 *
 *---------------------------------------------------------------------*/

void setEthernetAddress(struct sr_instance* sr, const unsigned char* addr)
{
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    assert(sr->if_list);
    
    if_walker = sr->if_list;
    while(if_walker->next)
    {if_walker = if_walker->next; }

    /* -- copy address -- */
    memcpy(if_walker->addr,addr,6);

} /* -- setEthernetAddress -- */

/*--------------------------------------------------------------------- 
 * Method: setEthernetIp(..)
 * Scope: Global
 *
 * set the IP address of the LAST interface in the interface list
 *
 *---------------------------------------------------------------------*/

void setEthernetIp(struct sr_instance* sr, uint32_t ip_nbo)
{
    struct sr_if* if_walker = 0;

    /* -- REQUIRES -- */
    assert(sr->if_list);
    
    if_walker = sr->if_list;
    while(if_walker->next)
    {if_walker = if_walker->next; }

    /* -- copy address -- */
    if_walker->ip = ip_nbo;

} /* -- setEthernetIp -- */

/*--------------------------------------------------------------------- 
 * Method: printInterfaceList(..)
 * Scope: Global
 *
 * print out the list of interfaces to stdout
 *
 *---------------------------------------------------------------------*/

void printInterfaceList(struct sr_instance* sr)
{
    struct sr_if* if_walker = 0;

    if(sr->if_list == 0)
    {
        printf(" Interface list empty \n");
        return;
    }

    if_walker = sr->if_list;
    
    printInterface(if_walker);
    while(if_walker->next)
    {
        if_walker = if_walker->next; 
        printInterface(if_walker);
    }

} /* -- printInterfaceList -- */

/*--------------------------------------------------------------------- 
 * Method: printInterface(..)
 * Scope: Global
 *
 * print out a single interface to stdout
 *
 *---------------------------------------------------------------------*/

void printInterface(struct sr_if* iface)
{
    struct in_addr ip_addr;

    /* -- REQUIRES --*/
    assert(iface);
    assert(iface->name);

    ip_addr.s_addr = iface->ip;

    Debug("%s\tHWaddr",iface->name);
    DebugMAC(iface->addr);
    Debug("\n");
    Debug("\tinet addr %s\n",inet_ntoa(ip_addr));
} /* -- printInterface -- */
