// Re-defining some structs here, since including kernel's header may cause
// compilation to fail due to missing symbols which cannot be referred from BPF (e.g. printk)

#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/dmaengine.h>
#include <net/sock.h>
#include <linux/compiler.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/poll.h>
#include <net/inet_sock.h>
#include <net/request_sock.h>
#include <net/inet_timewait_sock.h>
#include <uapi/linux/tcp.h>
#include <linux/rh_kabi.h>

struct inet_bind_bucket;
struct tcp_congestion_ops;

/*
 * Pointers to address related TCP functions
 * (i.e. things that depend on the address family)
 */
struct inet_connection_sock_af_ops {
    int        (*queue_xmit)(struct sk_buff *skb, struct flowi *fl);
    void       (*send_check)(struct sock *sk, struct sk_buff *skb);
    int        (*rebuild_header)(struct sock *sk);
    void       (*sk_rx_dst_set)(struct sock *sk, const struct sk_buff *skb);
    int        (*conn_request)(struct sock *sk, struct sk_buff *skb);
    struct sock *(*syn_recv_sock)(struct sock *sk, struct sk_buff *skb,
                                  struct request_sock *req,
                                  struct dst_entry *dst);
    u16        net_header_len;
    u16        net_frag_header_len;
    u16        sockaddr_len;
    int        (*setsockopt)(struct sock *sk, int level, int optname,
                             char __user *optval, unsigned int optlen);
    int        (*getsockopt)(struct sock *sk, int level, int optname,
                             char __user *optval, int __user *optlen);
#ifdef CONFIG_COMPAT
    int        (*compat_setsockopt)(struct sock *sk,
            int level, int optname,
            char __user *optval, unsigned int optlen);
   int        (*compat_getsockopt)(struct sock *sk,
            int level, int optname,
            char __user *optval, int __user *optlen);
#endif
    void       (*addr2sockaddr)(struct sock *sk, struct sockaddr *);
    int        (*bind_conflict)(const struct sock *sk,
                                const struct inet_bind_bucket *tb, bool relax);
    void       (*mtu_reduced)(struct sock *sk);
};

/** inet_connection_sock - INET connection oriented sock
 *
 * @icsk_accept_queue:    FIFO of established children
 * @icsk_bind_hash:       Bind node
 * @icsk_timeout:     Timeout
 * @icsk_retransmit_timer: Resend (no ack)
 * @icsk_rto:        Retransmit timeout
 * @icsk_pmtu_cookie      Last pmtu seen by socket
 * @icsk_ca_ops          Pluggable congestion control hook
 * @icsk_af_ops          Operations which are AF_INET{4,6} specific
 * @icsk_ca_state:    Congestion control state
 * @icsk_retransmits:     Number of unrecovered [RTO] timeouts
 * @icsk_pending:     Scheduled timer event
 * @icsk_backoff:     Backoff
 * @icsk_syn_retries:      Number of allowed SYN (or equivalent) retries
 * @icsk_probes_out:      unanswered 0 window probes
 * @icsk_ext_hdr_len:     Network protocol overhead (IP/IPv6 options)
 * @icsk_ack:        Delayed ACK control data
 * @icsk_mtup;       MTU probing control data
 */
struct inet_connection_sock {
    /* inet_sock has to be the first member! */
    struct inet_sock     icsk_inet;
    struct request_sock_queue icsk_accept_queue;
    struct inet_bind_bucket      *icsk_bind_hash;
    unsigned long       icsk_timeout;
    struct timer_list    icsk_retransmit_timer;
    struct timer_list    icsk_delack_timer;
    __u32          icsk_rto;
    __u32          icsk_pmtu_cookie;
    const struct tcp_congestion_ops *icsk_ca_ops;
    const struct inet_connection_sock_af_ops *icsk_af_ops;
    unsigned int        (*icsk_sync_mss)(struct sock *sk, u32 pmtu);
    __u8           icsk_ca_state:6,
            icsk_ca_setsockopt:1,
            icsk_ca_dst_locked:1;
    __u8           icsk_retransmits;
    __u8           icsk_pending;
    __u8           icsk_backoff;
    __u8           icsk_syn_retries;
    __u8           icsk_probes_out;
    __u16          icsk_ext_hdr_len;
    struct {
        __u8        pending;  /* ACK is pending          */
        __u8        quick;    /* Scheduled number of quick acks    */
        __u8        pingpong;     /* The session is interactive       */
        __u8        blocked;  /* Delayed ACK was blocked by socket lock */
        __u32       ato;     /* Predicted tick of soft clock      */
        unsigned long    timeout;  /* Currently scheduled timeout          */
        __u32       lrcvtime;     /* timestamp of last received data packet */
        __u16       last_seg_size; /* Size of last incoming segment     */
        __u16       rcv_mss;  /* MSS used for delayed ACK decisions    */
    } icsk_ack;
    struct {
        int         enabled;

        /* Range of MTUs to search */
        int         search_high;
        int         search_low;

        /* Information on the current probe. */
        int         probe_size;
    } icsk_mtup;
    u32            icsk_ca_priv[16];
    u32            icsk_user_timeout;
#define ICSK_CA_PRIV_SIZE  (16 * sizeof(u32))
};

#define ICSK_TIME_RETRANS  1  /* Retransmit timer */
#define ICSK_TIME_DACK    2  /* Delayed ack timer */
#define ICSK_TIME_PROBE0   3  /* Zero window probe timer */
#define ICSK_TIME_EARLY_RETRANS 4  /* Early retransmit timer */
#define ICSK_TIME_LOSS_PROBE   5  /* Tail loss probe timer */

enum inet_csk_ack_state_t {
    ICSK_ACK_SCHED = 1,
    ICSK_ACK_TIMER  = 2,
    ICSK_ACK_PUSHED = 4,
    ICSK_ACK_PUSHED2 = 8
};

/* TCP Fast Open */
#define TCP_FASTOPEN_COOKIE_MIN	4	/* Min Fast Open Cookie size in bytes */
#define TCP_FASTOPEN_COOKIE_MAX	16	/* Max Fast Open Cookie size in bytes */
#define TCP_FASTOPEN_COOKIE_SIZE 8	/* the size employed by this impl. */

/* TCP Fast Open Cookie as stored in memory */
struct tcp_fastopen_cookie {
    s8	len;
    u8	val[TCP_FASTOPEN_COOKIE_MAX];
    bool	exp;	/* In RFC6994 experimental option format */
};

/* This defines a selective acknowledgement block. */
struct tcp_sack_block_wire {
    __be32	start_seq;
    __be32	end_seq;
};

struct tcp_sack_block {
    u32	start_seq;
    u32	end_seq;
};

/*These are used to set the sack_ok field in struct tcp_options_received */
#define TCP_SACK_SEEN     (1 << 0)   /*1 = peer is SACK capable, */
#define TCP_FACK_ENABLED  (1 << 1)   /*1 = FACK is enabled locally*/
#define TCP_DSACK_SEEN    (1 << 2)   /*1 = DSACK was received from peer*/

struct tcp_options_received {
/*	PAWS/RTTM data	*/
    long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */
    u32	ts_recent;	/* Time stamp to echo next		*/
    u32	rcv_tsval;	/* Time stamp value             	*/
    u32	rcv_tsecr;	/* Time stamp echo reply        	*/
    union {
      u16 data;
      struct {
        u16 saw_tstamp : 1;	/* Saw TIMESTAMP on last packet		*/
        u16 tstamp_ok : 1;	/* TIMESTAMP seen on SYN packet		*/
        u16 dsack : 1;	/* D-SACK is scheduled			*/
        u16 wscale_ok : 1;	/* Wscale seen on SYN packet		*/
        u16 sack_ok : 4;	/* SACK seen on SYN packet		*/
        u16 snd_wscale : 4;	/* Window scaling received from sender	*/
        u16 rcv_wscale : 4;	/* Window scaling to send to receiver	*/
      } fields;
    } opt_bits;
    u8	num_sacks;	/* Number of SACK blocks		*/
    u16	user_mss;	/* mss requested by user in ioctl	*/
    u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */
};

/* This is the max number of SACKS that we'll generate and process. It's safe
 * to increase this, although since:
 *   size = TCPOLEN_SACK_BASE_ALIGNED (4) + n * TCPOLEN_SACK_PERBLOCK (8)
 * only four options will fit in a standard TCP header */
#define TCP_NUM_SACKS 4

struct tcp_request_sock_ops;

struct tcp_request_sock {
    struct inet_request_sock 	req;
    const struct tcp_request_sock_ops *af_specific;
    struct sock			*listener; /* needed for TFO */
    u32				rcv_isn;
    u32				snt_isn;
    u32				snt_synack; /* synack sent time */
    u32				last_oow_ack_time; /* last SYNACK */
    u32				rcv_nxt; /* the ack # by SYNACK. For
						  * FastOpen it's the seq#
						  * after data-in-SYN.
						  */
};

struct tcp_sock {
    /* inet_connection_sock has to be the first member of tcp_sock */
    struct inet_connection_sock	inet_conn;
    u16	tcp_header_len;	/* Bytes of tcp header to send		*/
    u16	gso_segs;	/* Max number of segs per GSO packet	*/

/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 */
    __be32	pred_flags;

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 */
    u64	bytes_received;	/* RFC4898 tcpEStatsAppHCThruOctetsReceived
				 * sum(delta(rcv_nxt)), or how many bytes
				 * were acked.
				 */
    u32	segs_in;	/* RFC4898 tcpEStatsPerfSegsIn
				 * total number of segments in.
				 */
    u32	rcv_nxt;	/* What we want to receive next 	*/
    u32	copied_seq;	/* Head of yet unread data		*/
    u32	rcv_wup;	/* rcv_nxt on last window update sent	*/
    u32	snd_nxt;	/* Next sequence we send		*/
    u32	segs_out;	/* RFC4898 tcpEStatsPerfSegsOut
				 * The total number of segments sent.
				 */
    u64	bytes_acked;	/* RFC4898 tcpEStatsAppHCThruOctetsAcked
				 * sum(delta(snd_una)), or how many bytes
				 * were acked.
				 */
    struct u64_stats_sync syncp; /* protects 64bit vars (cf tcp_get_info()) */

    u32	snd_una;	/* First byte we want an ack for	*/
    u32	snd_sml;	/* Last byte of the most recently transmitted small packet */
    u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */
    u32	lsndtime;	/* timestamp of last sent data packet (for restart window) */
    u32	last_oow_ack_time;  /* timestamp of last out-of-window ACK */

    u32	tsoffset;	/* timestamp offset */

    struct list_head tsq_node; /* anchor in tsq_tasklet.head list */
    unsigned long	tsq_flags;

    /* Data for direct copy to user */
    struct {
        struct sk_buff_head	prequeue;
        struct task_struct	*task;
        struct iovec		*iov;
        int			memory;
        int			len;
#ifdef CONFIG_NET_DMA_RH_KABI
        RH_KABI_DEPRECATE(struct dma_chan *,		dma_chan)
		RH_KABI_DEPRECATE(int,				wakeup)
		RH_KABI_DEPRECATE(struct dma_pinned_list *,	pinned_list)
		RH_KABI_DEPRECATE(dma_cookie_t,			dma_cookie)
#endif
    } ucopy;

    u32	snd_wl1;	/* Sequence for window update		*/
    u32	snd_wnd;	/* The window we expect to receive	*/
    u32	max_window;	/* Maximal window ever seen from peer	*/
    u32	mss_cache;	/* Cached effective mss, not including SACKS */

    u32	window_clamp;	/* Maximal window to advertise		*/
    u32	rcv_ssthresh;	/* Current window clamp			*/

    u16	advmss;		/* Advertised MSS			*/
    u8	unused;
    u8	nonagle     : 4,/* Disable Nagle algorithm?             */
    thin_lto    : 1,/* Use linear timeouts for thin streams */
    thin_dupack : 1,/* Fast retransmit on first dupack      */
    repair      : 1,
            frto        : 1;/* F-RTO (RFC5682) activated in CA_Loss */
    u8	repair_queue;
    u8	do_early_retrans:1,/* Enable RFC5827 early-retransmit  */
    syn_data:1,	/* SYN includes data */
    syn_fastopen:1,	/* SYN includes Fast Open option */
    syn_fastopen_exp:1,/* SYN includes Fast Open exp. option */
    syn_data_acked:1,/* data in SYN is acked by SYN-ACK */
    is_cwnd_limited:1;/* forward progress limited by snd_cwnd? */
    u32	tlp_high_seq;	/* snd_nxt at the time of TLP retransmit. */

/* RTT measurement */
    u32	srtt_us;	/* smoothed round trip time << 3 in usecs */
    u32	mdev_us;	/* medium deviation			*/
    u32	mdev_max_us;	/* maximal mdev for the last rtt period	*/
    u32	rttvar_us;	/* smoothed mdev_max			*/
    u32	rtt_seq;	/* sequence number to update rttvar	*/

    u32	packets_out;	/* Packets which are "in flight"	*/
    u32	retrans_out;	/* Retransmitted packets out		*/
    u32	max_packets_out;  /* max packets_out in last window */
    u32	max_packets_seq;  /* right edge of max_packets_out flight */

    u16	urg_data;	/* Saved octet of OOB data and control flags */
    u8	ecn_flags;	/* ECN status bits.			*/
    u8	reordering;	/* Packet reordering metric.		*/
    u32	snd_up;		/* Urgent pointer		*/

    u8	keepalive_probes; /* num of allowed keep alive probes	*/
/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
    struct tcp_options_received rx_opt;

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
    u32	snd_ssthresh;	/* Slow start size threshold		*/
    u32	snd_cwnd;	/* Sending congestion window		*/
    u32	snd_cwnd_cnt;	/* Linear increase counter		*/
    u32	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this */
    u32	snd_cwnd_used;
    u32	snd_cwnd_stamp;
    u32	prior_cwnd;	/* Congestion window at start of Recovery. */
    u32	prr_delivered;	/* Number of newly delivered packets to
				 * receiver in Recovery. */
    u32	prr_out;	/* Total number of pkts sent during Recovery. */

    u32	rcv_wnd;	/* Current receiver window		*/
    u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */
    u32	notsent_lowat;	/* TCP_NOTSENT_LOWAT */
    u32	pushed_seq;	/* Last pushed seq, required to talk to windows */
    u32	lost_out;	/* Lost packets			*/
    u32	sacked_out;	/* SACK'd packets			*/
    u32	fackets_out;	/* FACK'd packets			*/
    u32	tso_deferred;

    /* from STCP, retrans queue hinting */
    struct sk_buff* lost_skb_hint;
    struct sk_buff *retransmit_skb_hint;

    /* OOO segments go in this rbtree. Socket lock must be held. */
    struct rb_root	out_of_order_queue;
    struct sk_buff	*ooo_last_skb; /* cache rb_last(out_of_order_queue) */

    /* SACKs data, these 2 need to be together (see tcp_options_write) */
    struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */
    struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/

    struct tcp_sack_block recv_sack_cache[4];

    struct sk_buff *highest_sack;   /* skb just after the highest
					 * skb with SACKed bit set
					 * (validity guaranteed only if
					 * sacked_out > 0)
					 */

    int     lost_cnt_hint;
    u32     retransmit_high;	/* L-bits may be on up to this seqno */

    u32	lost_retrans_low;	/* Sent seq after any rxmit (lowest) */

    u32	prior_ssthresh; /* ssthresh saved at recovery start	*/
    u32	high_seq;	/* snd_nxt at onset of congestion	*/

    u32	retrans_stamp;	/* Timestamp of the last retransmit,
				 * also used in SYN-SENT to remember stamp of
				 * the first SYN. */
    u32	undo_marker;	/* snd_una upon a new recovery episode. */
    int	undo_retrans;	/* number of undoable retransmissions. */
    u32	total_retrans;	/* Total retransmits for entire connection */

    u32	urg_seq;	/* Seq of received urgent pointer */
    unsigned int		keepalive_time;	  /* time before keep alive takes place */
    unsigned int		keepalive_intvl;  /* time interval between keep alive probes */

    int			linger2;

/* Receiver side RTT estimation */
    struct {
        u32	rtt;
        u32	seq;
        u32	time;
    } rcv_rtt_est;

/* Receiver queue space */
    struct {
        int	space;
        u32	seq;
        u32	time;
    } rcvq_space;

/* TCP-specific MTU probe information. */
    struct {
        u32		  probe_seq_start;
        u32		  probe_seq_end;
    } mtu_probe;
    u32	mtu_info; /* We received an ICMP_FRAG_NEEDED / ICMPV6_PKT_TOOBIG
			   * while socket was owned by user.
			   */

#ifdef CONFIG_TCP_MD5SIG
    /* TCP AF-Specific parts; only used by MD5 Signature support so far */
	const struct tcp_sock_af_ops	*af_specific;

/* TCP MD5 Signature Option information */
	struct tcp_md5sig_info	__rcu *md5sig_info;
#endif

/* TCP fastopen related information */
    struct tcp_fastopen_request *fastopen_req;
    /* fastopen_rsk points to request_sock that resulted in this big
     * socket. Used to retransmit SYNACKs etc.
     */
    struct request_sock *fastopen_rsk;
};

enum tsq_flags {
    TSQ_THROTTLED,
    TSQ_QUEUED,
    TCP_TSQ_DEFERRED,	   /* tcp_tasklet_func() found socket was owned */
    TCP_WRITE_TIMER_DEFERRED,  /* tcp_write_timer() found socket was owned */
    TCP_DELACK_TIMER_DEFERRED, /* tcp_delack_timer() found socket was owned */
    TCP_MTU_REDUCED_DEFERRED,  /* tcp_v{4|6}_err() could not call
				    * tcp_v{4|6}_mtu_reduced()
				    */
};

struct tcp_timewait_sock {
    struct inet_timewait_sock tw_sk;
    u32			  tw_rcv_nxt;
    u32			  tw_snd_nxt;
    u32			  tw_rcv_wnd;
    u32			  tw_ts_offset;
    u32			  tw_ts_recent;

    /* The time we sent the last out-of-window ACK: */
    u32			  tw_last_oow_ack_time;

    long			  tw_ts_recent_stamp;
#ifdef CONFIG_TCP_MD5SIG
    struct tcp_md5sig_key	  *tw_md5_key;
#endif
};
