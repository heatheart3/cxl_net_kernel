#include "br_private.h"


enum cxl_connection_status
{
    CONNECTION_CLOSED,
    CONNECTION_HALF_OPEN,
    CONNECTION_OPEN,
};

struct cxl_ring_sender{
    enum cxl_connection_status c_status;
    u32 send_budget;
    u32 current_head;
    struct cxl_skb_ring* ring;
};

struct cxl_ring_recver{
    enum cxl_connection_status c_status;
    u32 current_tail;
    struct cxl_skb_ring* ring;
};


