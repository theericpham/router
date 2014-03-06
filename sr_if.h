/*-----------------------------------------------------------------------------
 * file:  sr_if.h
 * date:  Sun Oct 06 14:13:13 PDT 2002 
 * Contact: casado@stanford.edu 
 *
 * Description:
 *
 * Data structures and methods for handeling interfaces
 *
 *---------------------------------------------------------------------------*/

#ifndef sr_INTERFACE_H
#define sr_INTERFACE_H

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#ifdef _SOLARIS_
#include </usr/include/sys/int_types.h>
#endif /* SOLARIS */

#ifdef _DARWIN_
#include <inttypes.h>
#endif

#include "sr_protocol.h"

struct Instance;

/* ----------------------------------------------------------------------------
 * struct Interface
 *
 * Node in the interface list for each router
 *
 * -------------------------------------------------------------------------- */

struct Interface
{
  char name[sr_IFACE_NAMELEN];
  unsigned char addr[ETHER_ADDR_LEN];
  uint32_t ip;
  uint32_t speed;
  struct Interface* next;
};

struct Interface* getInterface(struct Instance* sr, const char* name);
void addInterface(struct Instance*, const char*);
void setEthernetAddress(struct Instance*, const unsigned char*);
void setEthernetIp(struct Instance*, uint32_t ip_nbo);
void printInterfaceList(struct Instance*);
void printInterface(struct Interface*);

#endif /* --  sr_INTERFACE_H -- */
