#include "errno.h"
#include "fcntl.h"
#include "kstat.h"
#include "stropts.h"
#include "unistd.h"
#include "sys/ddi.h"
#include "sys/dld.h"
#include "sys/dlpi.h"
#include "sys/kstat.h"
#include "sys/mac.h"
#include "sys/sunddi.h"
#include "sys/socket.h"
#include "sys/sockio.h"
#include "sys/types.h"
#include "net/if.h"
#include "net/route.h"

#ifndef RTM_GETALL
#define RTM_GETALL 0x11
#endif

// So we don't need private dld_ioc.h header
#define DLD_IOC         0x0D1D
#define	AGGR_IOC	0x0A66
#define	VNIC_IOC	0x0171
#define	SIMNET_IOC	0x5132
#define	IPTUN_IOC	0x454A
#define	BRIDGE_IOC	0xB81D
#define	IBPART_IOC	0x6171

#define DLD_IOC_CMD(modid, cmdid)   (((uint_t)(modid) << 16) | (cmdid))
#define DLDIOC(cmdid)               DLD_IOC_CMD(DLD_IOC, (cmdid))

// https://github.com/rust-lang/rust-bindgen/issues/753#issuecomment-308901773
const int __DLDIOC_MACADDRGET = DLDIOC(0x15);
const int __SIOCGLIFNUM = _IOWR('i', 130, struct lifnum);
const int __SIOCGLIFCONF = _IOWRN('i', 165, 16);
const int __SIOCGLIFNETMASK = _IOWR('i', 125, struct lifreq);
const int __SIOCGLIFFLAGS = _IOWR('i', 117, struct lifreq);
const int __SIOCGLIFDADSTATE = _IOWR('i', 190, struct lifreq);
const int __SIOCGLIFINDEX = _IOWR('i', 133, struct lifreq);

// So we don't need private simnet.h header
#define	SIMNETIOC(cmdid)	DLD_IOC_CMD(SIMNET_IOC, (cmdid))

const int __SIMNET_IOC_CREATE = SIMNETIOC(1);
const int __SIMNET_IOC_DELETE =	SIMNETIOC(2);
const int __SIMNET_IOC_INFO = SIMNETIOC(3);
const int __SIMNET_IOC_MODIFY = SIMNETIOC(4);

// So we don't need private vnic.h header

#define	VNICIOC(cmdid)		DLD_IOC_CMD(VNIC_IOC, (cmdid))
const int __VNIC_IOC_CREATE = VNICIOC(1);
const int __VNIC_IOC_DELETE = VNICIOC(2);
const int __VNIC_IOC_INFO = VNICIOC(3);
const int __VNIC_IOC_MODIFY = VNICIOC(4);
