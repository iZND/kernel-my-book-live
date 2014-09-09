#include <linux/err.h>
#include <linux/module.h>
#include <net/ip.h>
#include <net/xfrm.h>
#include <net/ah.h>
#include <linux/crypto.h>
#include <linux/pfkeyv2.h>
#include <linux/spinlock.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <crypto/authenc.h>
#include <linux/highmem.h>
#include <crypto/hash.h>

#define DEBUG_AH
#ifndef DEBUG_AH
#	define AH_DUMP_PKT		print_hex_dump
#else
#	define AH_DUMP_PKT(arg...)
#endif

/**
 * @brief SKB private data for AH stored in skb cb field
 *
 * @tmp_req	  - temporary ahash/aead request
 * @icv_trunc_len - AH ICV length for software AH
 * @nh		  - Next header for hardware offload AH
 *
 */
struct ah_skb_cb {
	void	*tmp_req;
	u16	icv_trunc_len;
	u8	nh;
};

#define AH_SKB_CB(__skb) ((struct ah_skb_cb *)&((__skb)->cb[0]))

/**
 * @brief AH work buffer (union) for software AH
 * @iph	- IP header access
 * @buf - byte address access
 * @note Used to save IP header and IP options
 *
 */
union ah_tmp_iph {
	struct iphdr	iph;
	char 		buf[60];
};

#define AH_WORK_BUF_MAX_LEN	sizeof(union ah_tmp_iph)

/*
 * Allocate an ahash request structure with extra space for structure
 * ah_tmp_iph (scatch pad), ICV (input save ICV), working ICV
 * (space for hash algorithm to store ICV), and SG.
 *
 */
static void *ah_alloc_tmp(struct crypto_ahash *ahash, int nfrags)
{
	unsigned int len;

	len  = AH_WORK_BUF_MAX_LEN;
	len += MAX_AH_AUTH_LEN;
	len += crypto_ahash_digestsize(ahash);
	len += sizeof(struct ahash_request) + crypto_ahash_reqsize(ahash);
	len += ALIGN(len, __alignof__(struct scatterlist));
	len += sizeof(struct scatterlist) * nfrags;

	return kmalloc(len, GFP_ATOMIC);
}

static inline void ah_free_tmp(void *tmp)
{
	kfree(tmp);
}

static inline union ah_tmp_iph *ah_tmp_work_buf(void *tmp)
{
	return tmp;
}

static inline u8 *ah_tmp_icv(union ah_tmp_iph *tmp)
{
	return (u8 *) (tmp + 1);
}

static inline u8 *ah_tmp_work_icv(u8 *tmp)
{
	return tmp + MAX_AH_AUTH_LEN;
}

static inline struct ahash_request *ah_tmp_req(struct crypto_ahash *ahash,
					       u8 *tmp)
{
	struct ahash_request *req = (struct ahash_request *) (tmp +
					crypto_ahash_digestsize(ahash));
	ahash_request_set_tfm(req, ahash);
	return req;
}

static inline struct scatterlist *ah_tmp_sg(struct crypto_ahash  *ahash,
					    struct ahash_request *req)
{
	return (void *) ALIGN((unsigned long) (req + 1) +
			      crypto_ahash_reqsize(ahash),
			      __alignof__(struct scatterlist));
}

/*
 * Allocate an aead request structure with extra space for structure
 * SG.
 *
 */
static void *ah_alloc_aead_tmp(struct crypto_aead *aead, int nfrags)
{
	unsigned int len;

	len  = sizeof(struct aead_request) + crypto_aead_reqsize(aead);
	len += ALIGN(len, __alignof__(struct scatterlist));
	len += sizeof(struct scatterlist) * nfrags;

	return kmalloc(len, GFP_ATOMIC);
}

static inline void ah_free_aead_tmp(void *tmp)
{
	kfree(tmp);
}

static inline struct aead_request *ah_tmp_aead_req(struct crypto_aead *aead,
					      	   void *tmp)
{
	struct aead_request *req = (struct aead_request *) tmp;
	aead_request_set_tfm(req, aead);
	return req;
}

static inline struct scatterlist *ah_tmp_aead_sg(struct crypto_aead *aead,
					    	 struct aead_request *req)
{
	return (void *) ALIGN((unsigned long) (req + 1) +
			      crypto_aead_reqsize(aead),
			      __alignof__(struct scatterlist));
}
static inline struct scatterlist *ah_tmp_aead_dsg(struct scatterlist *sg,
		unsigned int nfrags)
{
	return (void *) ((unsigned long) sg +
			sizeof(struct scatterlist) * nfrags);

}

/* Clear mutable options and find final destination to substitute
 * into IP header for icv calculation. Options are already checked
 * for validity, so paranoia is not required. */
int ip_clear_mutable_options(struct iphdr *iph, __be32 *daddr)
{
	unsigned char * optptr = (unsigned char*)(iph+1);
	int  l = iph->ihl*4 - sizeof(struct iphdr);
	int  optlen;

	while (l > 0) {
		switch (*optptr) {
		case IPOPT_END:
			return 0;
		case IPOPT_NOOP:
			l--;
			optptr++;
			continue;
		}
		optlen = optptr[1];
		if (optlen<2 || optlen>l)
			return -EINVAL;
		switch (*optptr) {
		case IPOPT_SEC:
		case 0x85:	/* Some "Extended Security" crap. */
		case IPOPT_CIPSO:
		case IPOPT_RA:
		case 0x80|21:	/* RFC1770 */
			break;
		case IPOPT_LSRR:
		case IPOPT_SSRR:
			if (optlen < 6)
				return -EINVAL;
			memcpy(daddr, optptr+optlen-4, 4);
			/* Fall through */
		default:
			memset(optptr, 0, optlen);
		}
		l -= optlen;
		optptr += optlen;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(ip_clear_mutable_options);

/*******************************************************************************
 * AH Software Functions
 *
 *******************************************************************************
 */
static int ah_output_done2(struct sk_buff *skb, int err)
{
	void 		   *req_tmp = AH_SKB_CB(skb)->tmp_req;
	struct iphdr	   *iph;
	struct iphdr	   *top_iph;
	union ah_tmp_iph   *tmp_iph;
	struct ip_auth_hdr *ah;
	char	*icv;
	char	*work_icv;

	if (err < 0)
		goto out;

	tmp_iph  = ah_tmp_work_buf(req_tmp);
	icv      = ah_tmp_icv(tmp_iph);
	work_icv = ah_tmp_work_icv(icv);
	iph      = &tmp_iph->iph;
	top_iph  = ip_hdr(skb);
	ah 	 = ip_auth_hdr(skb);

	/* Set ICV in AH header */
	memcpy(ah->auth_data, work_icv, AH_SKB_CB(skb)->icv_trunc_len);

	/* Restore mute fields */
	top_iph->tos 	  = iph->tos;
	top_iph->ttl 	  = iph->ttl;
	top_iph->frag_off = iph->frag_off;
	if (top_iph->ihl != 5) {
		top_iph->daddr = iph->daddr;
		memcpy(top_iph+1, iph+1, top_iph->ihl*4 - sizeof(struct iphdr));
	}

	AH_DUMP_PKT(KERN_INFO, "AH output sw done: ", DUMP_PREFIX_ADDRESS,
   		16, 4, skb->data, skb->len, 1);

out:
	kfree(req_tmp);
	return err;
}

static void ah_output_done(struct crypto_async_request *base, int err)
{
	struct sk_buff *skb = base->data;

	xfrm_output_resume(skb, ah_output_done2(skb, err));
}

static int ah_output_sw(struct xfrm_state *x, struct sk_buff *skb)
{
	int err;
	struct iphdr *iph, *top_iph;
	struct ip_auth_hdr *ah;
	struct ah_data     *ahp;
	struct ahash_request *areq;
	struct scatterlist   *sg;
	int 		 nfrags;
	void 		 *req_tmp = NULL;
	union ah_tmp_iph *tmp_iph;
	char   		 *icv;
	char   		 *work_icv;
	struct sk_buff 	 *trailer;

	/* SKB transport, network, and mac header pointers are set by
	   transport or tunnel modules.

	  Transport Input:
	  -----------------------
	  | IP | Rsvd | Payload |
	  -----------------------
		      ^
		      |
		      skb.data

	  Tunnel Input:
	  ----------------------------------------
	  | Outer IP | Rsvd | Inner IP | Payload |
	  ----------------------------------------
			    ^
			    |
			    skb.data
	*/

	AH_DUMP_PKT(KERN_INFO, "AH output sw : ", DUMP_PREFIX_ADDRESS,
		    16, 4, skb->data, skb->len, 1);

	skb_push(skb, -skb_network_offset(skb));

	/* Find # of fragments */
	if ((err = skb_cow_data(skb, 0, &trailer)) < 0)
		goto error;
	nfrags = err;

	/* Allocate temp request */
	ahp      = x->data;
	req_tmp  = ah_alloc_tmp(ahp->utfm.atfm, nfrags);
	if (!req_tmp) {
		err = -ENOMEM;
		goto error;
	}

	AH_SKB_CB(skb)->tmp_req       = req_tmp;
	AH_SKB_CB(skb)->icv_trunc_len = ahp->icv_trunc_len;
	tmp_iph = ah_tmp_work_buf(req_tmp);
	icv	= ah_tmp_icv(tmp_iph);
	work_icv = ah_tmp_work_icv(icv);
	areq    = ah_tmp_req(ahp->utfm.atfm, work_icv);
	sg      = ah_tmp_sg(ahp->utfm.atfm, areq);

	top_iph = ip_hdr(skb);
	iph     = &tmp_iph->iph;

	/* Save IP header to compute hash */
	iph->tos = top_iph->tos;
	iph->ttl = top_iph->ttl;
	iph->frag_off = top_iph->frag_off;
	if (top_iph->ihl != 5) {
		if ((top_iph->ihl << 2) > AH_WORK_BUF_MAX_LEN) {
			err = -EINVAL;
			goto error;
		}
		iph->daddr = top_iph->daddr;
		memcpy(iph+1, top_iph+1, top_iph->ihl*4 - sizeof(struct iphdr));
		err = ip_clear_mutable_options(top_iph, &top_iph->daddr);
		if (err)
			goto error;
	}

	/* Set AH header */
	ah = ip_auth_hdr(skb);
	ah->nexthdr = *skb_mac_header(skb);
	*skb_mac_header(skb) = IPPROTO_AH;

	/* Mute field for hash */
	top_iph->tos = 0;
	top_iph->tot_len = htons(skb->len);
	top_iph->frag_off = 0;
	top_iph->ttl = 0;
	top_iph->check = 0;

	/* Set AH fields */
	ah->hdrlen  = (XFRM_ALIGN8(sizeof(*ah) + ahp->icv_trunc_len) >> 2) - 2;
	ah->reserved = 0;
	ah->spi      = x->id.spi;
	ah->seq_no   = htonl(XFRM_SKB_CB(skb)->seq.output);

	/* Mute AH for hash */
	memset(ah->auth_data, 0, ahp->icv_trunc_len);

	/* Setup SG for hash op */
	sg_init_table(sg, nfrags);
	skb_to_sgvec(skb, sg, 0, skb->len);
	ahash_request_set_callback(areq, 0, ah_output_done, skb);
	ahash_request_set_crypt(areq, sg, work_icv, skb->len);

	err = crypto_ahash_digest(areq);
	if (err == -EINPROGRESS)
		goto out;
	if (err < 0)
		goto error;

	return ah_output_done2(skb, err);

error:
	if (req_tmp)
		ah_free_tmp(req_tmp);
out:
	return err;
}

static int ah_input_done2(struct sk_buff *skb, int err)
{
	void 		   *req_tmp = AH_SKB_CB(skb)->tmp_req;
	struct iphdr	   *top_iph;
	struct ip_auth_hdr *ah;
	union ah_tmp_iph   *tmp_iph;
	int 	ah_hlen;
	int 	ihl;
	char    *icv;
	char    *work_icv;
	int	nexthdr;

	if (err < 0)
		goto out;

	tmp_iph = ah_tmp_work_buf(req_tmp);
	icv	= ah_tmp_icv(tmp_iph);
	work_icv = ah_tmp_work_icv(icv);

	/* Verify ICV */
	if (memcmp(icv, work_icv, AH_SKB_CB(skb)->icv_trunc_len)) {
		err = -EBADMSG;
		goto out;
	}

	top_iph = ip_hdr(skb);
	ihl     = top_iph->ihl << 2;
	ah 	= (struct ip_auth_hdr *) ((u8 *) top_iph + ihl);
	nexthdr = ah->nexthdr;
	ah_hlen = (ah->hdrlen + 2) << 2;

	/* Remove AH header */
	skb->network_header += ah_hlen;
	memcpy(skb_network_header(skb), tmp_iph->buf, ihl);
	skb->transport_header = skb->network_header;
	__skb_pull(skb, ah_hlen + ihl);

	err = nexthdr;

	AH_DUMP_PKT(KERN_INFO, "AH input sw done: ", DUMP_PREFIX_ADDRESS,
		16, 4, skb->data, skb->len, 1);

out:
	kfree(req_tmp);
	return err;
}

static void ah_input_done(struct crypto_async_request *base, int err)
{
	struct sk_buff *skb = base->data;

	xfrm_input_resume(skb, ah_input_done2(skb, err));
}

static int ah_input_sw(struct xfrm_state *x, struct sk_buff *skb)
{
	int ah_hlen;
	int ihl;
	int nexthdr;
	int err = -EINVAL;
	struct iphdr 		*iph;
	struct ip_auth_hdr 	*ah;
	struct ah_data 		*ahp;
	struct sk_buff 		*trailer;
	struct ahash_request	*areq;
	struct scatterlist   	*sg;
	union ah_tmp_iph 	*tmp_iph;
	int	nfrags;
	void 	*req_tmp = NULL;
	char	*icv;
	char	*work_icv;

	/* SKB transport, network, and mac header pointers are set by
	   transport or tunnel modules.

	  Transport Input:
	  -----------------------
	  | IP | AH | Payload |
	  -----------------------
	       ^
	       |
	       skb.data

	  Tunnel Input:
	  ----------------------------------------
	  | Outer IP | AH | Inner IP | Payload |
	  ----------------------------------------
		     ^
		     |
		     skb.data
	*/

	AH_DUMP_PKT(KERN_INFO, "AH input sw : ", DUMP_PREFIX_ADDRESS,
		    16, 4, skb->data, skb->len, 1);

	if (!pskb_may_pull(skb, sizeof(*ah)))
		goto error;

	ah  = (struct ip_auth_hdr *)skb->data;
	ahp = x->data;
	nexthdr = ah->nexthdr;
	ah_hlen = (ah->hdrlen + 2) << 2;

	if (ah_hlen != XFRM_ALIGN8(sizeof(*ah) + ahp->icv_full_len) &&
	    ah_hlen != XFRM_ALIGN8(sizeof(*ah) + ahp->icv_trunc_len))
		goto error;

	if (!pskb_may_pull(skb, ah_hlen))
		goto error;

	/* We are going to _remove_ AH header to keep sockets happy,
	 * so... Later this can change. */
	if (skb_cloned(skb) &&
	    pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
		goto error;

	/* Find # of fragment */
	if ((err = skb_cow_data(skb, 0, &trailer)) < 0)
		goto error;
	nfrags  = err;

	skb->ip_summed = CHECKSUM_NONE;

	ah  = (struct ip_auth_hdr *)skb->data;
	iph = ip_hdr(skb);

	/* Allocate temp ahash request */
	req_tmp = ah_alloc_tmp(ahp->utfm.atfm, nfrags);
	if (!req_tmp) {
		err = -ENOMEM;
		goto error;
	}
	AH_SKB_CB(skb)->tmp_req       = req_tmp;
	AH_SKB_CB(skb)->icv_trunc_len = ahp->icv_trunc_len;
	tmp_iph = ah_tmp_work_buf(req_tmp);
	icv	= ah_tmp_icv(tmp_iph);
	work_icv = ah_tmp_work_icv(icv);
	areq    = ah_tmp_req(ahp->utfm.atfm, work_icv);
	sg      = ah_tmp_sg(ahp->utfm.atfm, areq);

	ihl = skb->data - skb_network_header(skb);
	if (ihl > AH_WORK_BUF_MAX_LEN) {
		err = -EBADMSG;
		goto error;
	}

	/* Save IP header for hash computation */
	memcpy(tmp_iph->buf, iph, ihl);

	/* Mute fields for hash op */
	iph->ttl = 0;
	iph->tos = 0;
	iph->frag_off = 0;
	iph->check = 0;
	if (ihl > sizeof(*iph)) {
		__be32 dummy;
		if (ip_clear_mutable_options(iph, &dummy))
			goto error;
	}

	/* Save ICV */
	memcpy(icv, ah->auth_data, ahp->icv_trunc_len);
	/* Mute ICV for hash op */
	memset(ah->auth_data, 0, ahp->icv_trunc_len);
	/* Add back IP header for SG */
	skb_push(skb, ihl);

	/* Setup SG */
	sg_init_table(sg, nfrags);
	skb_to_sgvec(skb, sg, 0, skb->len);
	ahash_request_set_callback(areq, 0, ah_input_done, skb);
	ahash_request_set_crypt(areq, sg, work_icv, skb->len);

	err = crypto_ahash_digest(areq);
	if (err == -EINPROGRESS)
		goto out;
	if (err < 0)
		goto error;

	return ah_input_done2(skb, err);

error:
	if (req_tmp)
		ah_free_tmp(req_tmp);
out:
	return err;
}

/*******************************************************************************
 * AH HW Offload Functions
 *
 *******************************************************************************
 */
static int ah_output_done2_hw(struct sk_buff *skb, int err)
{
	void *req_tmp = AH_SKB_CB(skb)->tmp_req;

	if (err < 0)
		goto out;

	AH_DUMP_PKT(KERN_INFO, "AH output hw: ", DUMP_PREFIX_ADDRESS,
		16, 4, skb->data, skb->len, 1);

out:
	kfree(req_tmp);
	return err;
}

static void ah_output_done_hw(struct crypto_async_request *base, int err)
{
	struct sk_buff *skb = base->data;

	xfrm_output_resume(skb, ah_output_done2_hw(skb, err));
}

static int ah_output_hw(struct xfrm_state *x, struct sk_buff *skb)
{
	struct ah_data      *ahp;
	struct aead_request *areq;
	struct scatterlist  *sg;
	struct scatterlist  *dsg;
	struct sk_buff 	    *trailer;
	void 	*req_tmp = NULL;
	int	err;
	int 	nfrags;
	unsigned int clen;

	/* For AH transport mode, skb.data is at IP header. skb.len
	   includes IP header and payload. skb network header, transport
	   header, and mac headers are updated by transport module code.

	  Input:
	  --------------------------------------------
	  | Network Hdr| Transport Hdr| IP | Payload |
	  --------------------------------------------
	                              ^
	      			      |
	     			      skb.data

	  For AH tunnel mode, outer IP header is formed by tunnel module.
	  skb network header, transport header, and mac header are updated
	  by tunnel module code.

   	  Input:
	  -----------------------------------------------------
	  | Outer IP | Rsvd | inner IP Header | Payload |
	  -----------------------------------------------------
	                    ^
			    |
			    skb.data
	*/

	ahp      = x->data;
	
	/* Find # fragment */
	if ((err = skb_cow_data(skb, 0, &trailer)) < 0)
		goto error;
	nfrags = err;

	/* Allocate temp request */
	req_tmp  = ah_alloc_aead_tmp(ahp->utfm.aeadtfm,  2 * nfrags);
	if (!req_tmp) {
		err = -ENOMEM;
		goto error;
	}

	AH_SKB_CB(skb)->tmp_req = req_tmp;
	areq    = ah_tmp_aead_req(ahp->utfm.aeadtfm, req_tmp);
	sg      = ah_tmp_aead_sg(ahp->utfm.aeadtfm, areq);
	dsg	= ah_tmp_aead_dsg(sg, nfrags);
	/* Set up SG - data will start at IP (inner) header (skb.data) */
	sg_init_table(sg, nfrags);
	skb_to_sgvec(skb, sg, 0, skb->len);
	clen = skb->len;
	skb_push(skb, -skb_network_offset(skb));
	skb_to_sgvec(skb, dsg, 0, skb->len);
	aead_request_set_callback(areq, 0, ah_output_done_hw, skb);
	aead_request_set_crypt(areq, sg, dsg, clen, NULL);

	/* For AH transport mode, SG is at IP header.

	  Input:
	  ----------------------
	  | Rsvd| IP | Payload |
	  ----------------------
	  Rsvd - space reserved for moved IP and added AH

	  Output:
	  ---------------------
	  | IP | AH | Payload |
	  ---------------------

	  For AH tunnel mode, outer IP header is formed by tunnel module.
	  SG is at inner IP header.

   	  Input:
	  ----------------------------------------
	  | Outer IP | Rsvd | inner IP | Payload |
	  ----------------------------------------
	  Rsvd - space reserved for added AH

   	  Output:
	  ----------------------------------------
	  | Outer IP | AH   | inner IP | Payload |
	  ----------------------------------------

	*/
	err = crypto_aead_encrypt(areq);
	if (err == -EINPROGRESS)
		goto out;
	if (err < 0)
		goto error;

	return ah_output_done2_hw(skb, err);

error:
	if (req_tmp)
		ah_free_tmp(req_tmp);
out:
	return err;
}

static int ah_input_done2_hw(struct sk_buff *skb, int err)
{
	void 		   *req_tmp = AH_SKB_CB(skb)->tmp_req;

	if (err < 0)
		goto out;

	err = AH_SKB_CB(skb)->nh;

	AH_DUMP_PKT(KERN_INFO, "AH input hw: ", DUMP_PREFIX_ADDRESS,
   		16, 4, skb->data, skb->len, 1);

out:
	kfree(req_tmp);
	return err;
}

static void ah_input_done_hw(struct crypto_async_request *base, int err)
{
	struct sk_buff *skb = base->data;

	xfrm_input_resume(skb, ah_input_done2_hw(skb, err));
}

static int ah_input_hw(struct xfrm_state *x, struct sk_buff *skb)
{
	int ah_hlen;
	int ihl;
	int err = -EINVAL;
	struct ip_auth_hdr  *ah;
	struct ah_data 	    *ahp;
	struct sk_buff	    *trailer;
	struct aead_request *areq;
	struct scatterlist  *sg;
	struct scatterlist  *dsg;
	int	nfrags;
	void 	*req_tmp = NULL;

	/* For AH transport/tunnel mode, skb.data is at AH header. skb.len
	   includes payload. skb network header, transport header, and
	   mac headers will be updated by transport module code.

	   Transport Input:
	   -------------------------
	   | IP Hdr | AH | Payload |
	   -------------------------
	            ^
	            |
	            skb.data and length start here

   	   Tunnel Input:
	   ------------------------------------
	   |Outer IP | AH | inner IP | Payload|
	   ------------------------------------
	             ^
		     |
		     skb.data and length start here
	*/

	AH_DUMP_PKT(KERN_INFO, "AH input hw : ", DUMP_PREFIX_ADDRESS,
	16, 4, skb->data, skb->len, 1);

	if (skb_cloned(skb) &&
	    pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
		goto error;

	/* Find # of fragment */
	if ((err = skb_cow_data(skb, 0, &trailer)) < 0)
		goto error;
	nfrags  = err;

	skb->ip_summed = CHECKSUM_NONE;

	ihl 	= skb->data - skb_network_header(skb);
	ah	= (struct ip_auth_hdr *) skb->data;
	ah_hlen = (ah->hdrlen + 2) << 2;
	AH_SKB_CB(skb)->nh = ah->nexthdr;

	/* Allocate temp request */
	ahp 	= x->data;
	req_tmp = ah_alloc_aead_tmp(ahp->utfm.aeadtfm,  2 * nfrags);
	if (!req_tmp) {
		err = -ENOMEM;
		goto error;
	}
	AH_SKB_CB(skb)->tmp_req       = req_tmp;
	areq    = ah_tmp_aead_req(ahp->utfm.aeadtfm, req_tmp);
	sg      = ah_tmp_aead_sg(ahp->utfm.aeadtfm, areq);
	dsg	= ah_tmp_aead_dsg(sg, nfrags);

	/* Init SG - data starts at AH header */
	sg_init_table(sg, nfrags);
	skb_to_sgvec(skb, sg, -ihl, skb->len + ihl);
	skb->network_header   += ah_hlen;
	skb->transport_header  = skb->network_header;
	__skb_pull(skb, ah_hlen);
	
	skb_to_sgvec(skb, dsg, -ihl, skb->len + ihl);
	aead_request_set_callback(areq, 0, ah_input_done_hw, skb);
	aead_request_set_crypt(areq, sg, dsg, skb->len + ah_hlen + ihl, NULL);

	/* For AH transport/tunnel mode, SG is at IP header.

	   Transport Input:
	   ----------------------------
	   | IP Hdr    | AH | Payload |
	   ----------------------------
	   IP Hdr - start of SG

	   Transport Output:
   	   ----------------------------
	   |       | IP Hdr | Payload |
	   ----------------------------

   	   Tunnel Input:
	   -------------------------------------
	   | Outer IP | AH | inner IP | Payload|
	   -------------------------------------
	   Outer IP Hdr - start of SG

   	   Tunnel Output:
	   -------------------------------------
	   | Outer IP | AH | inner IP | Payload|
	   -------------------------------------
	   Outer IP and AH left un-touch

	*/
	err = crypto_aead_decrypt(areq);
	if (err == -EINPROGRESS)
		goto out;

	if (err < 0)
		goto error;

	return ah_input_done2(skb, err);

error:
	if (req_tmp)
		ah_free_tmp(req_tmp);
out:
	return err;
}

static int ah_output(struct xfrm_state *x, struct sk_buff *skb)
{
	if ((x->alg_flags & XFRM_ALGO_FLAGS_OFFLOAD_AH) &&
	    (x->alg_flags & (XFRM_ALGO_FLAGS_OFFLOAD_TUNNEL |
	    		    XFRM_ALGO_FLAGS_OFFLOAD_TRANPORT)))
		return ah_output_hw(x, skb);
	else
		return ah_output_sw(x, skb);
}

static int ah_input(struct xfrm_state *x, struct sk_buff *skb)
{
	if ((x->alg_flags & XFRM_ALGO_FLAGS_OFFLOAD_AH) &&
	    (x->alg_flags & (XFRM_ALGO_FLAGS_OFFLOAD_TUNNEL |
	    		    XFRM_ALGO_FLAGS_OFFLOAD_TRANPORT)))
		return ah_input_hw(x, skb);
	else
		return ah_input_sw(x, skb);
}

static void ah4_err(struct sk_buff *skb, u32 info)
{
	struct net *net = dev_net(skb->dev);
	struct iphdr *iph = (struct iphdr*)skb->data;
	struct ip_auth_hdr *ah = (struct ip_auth_hdr*)(skb->data+(iph->ihl<<2));
	struct xfrm_state *x;

	if (icmp_hdr(skb)->type != ICMP_DEST_UNREACH ||
	    icmp_hdr(skb)->code != ICMP_FRAG_NEEDED)
		return;

	x = xfrm_state_lookup(net, (xfrm_address_t *)&iph->daddr, ah->spi, IPPROTO_AH, AF_INET);
	if (!x)
		return;
	printk(KERN_DEBUG "pmtu discovery on SA AH/%08x/%08x\n",
	       ntohl(ah->spi), ntohl(iph->daddr));
	xfrm_state_put(x);
}

static int ah_init_state(struct xfrm_state *x)
{
	struct ah_data 	      *ahp = NULL;
	struct xfrm_algo_desc *aalg_desc;
	struct crypto_ahash   *ahashtfm;
	struct crypto_aead    *aeadtfm;
	char 	alg_name[CRYPTO_MAX_ALG_NAME];
	char 	*key;
	int  	key_len;
	int	digest_size;
	struct rtattr *rta;
	struct ah_param {
		__be32 spi;
		__be32 seq;
	} *param;

	if (!x->aalg)
		goto error;

	if (x->encap)
		goto error;

	ahp = kzalloc(sizeof(*ahp), GFP_KERNEL);
	if (ahp == NULL)
		return -ENOMEM;

	/* Try AH hardware offload first */
	switch (x->props.mode) {
	case XFRM_MODE_TUNNEL:
		snprintf(alg_name, ARRAY_SIZE(alg_name),
			"tunnel(ah(%s))", x->aalg->alg_name);
		x->alg_flags |= XFRM_ALGO_FLAGS_OFFLOAD_TUNNEL
				| XFRM_ALGO_FLAGS_OFFLOAD_AH;
		break;
	case XFRM_MODE_TRANSPORT:
		snprintf(alg_name, ARRAY_SIZE(alg_name),
			"transport(ah(%s))", x->aalg->alg_name);
		x->alg_flags |= XFRM_ALGO_FLAGS_OFFLOAD_TRANPORT
				| XFRM_ALGO_FLAGS_OFFLOAD_AH;
		break;
	default:
		strncpy(alg_name, x->aalg->alg_name, ARRAY_SIZE(alg_name));
		break;
	}
	if (x->alg_flags & XFRM_ALGO_FLAGS_OFFLOAD_AH) {
		aeadtfm = crypto_alloc_aead(alg_name, 0, 0);
		if (IS_ERR(aeadtfm)) {
			/* No AH hardware offload, go to software AH */
			x->alg_flags &= ~(XFRM_ALGO_FLAGS_OFFLOAD_TUNNEL
					  | XFRM_ALGO_FLAGS_OFFLOAD_TRANPORT
					  | XFRM_ALGO_FLAGS_OFFLOAD_AH);
			aeadtfm  = NULL;
			ahashtfm = crypto_alloc_ahash(x->aalg->alg_name, 0, 0);
			if (IS_ERR(ahashtfm))
				goto error;
			ahp->utfm.atfm = ahashtfm;
		} else {
			ahashtfm     = NULL;
			ahp->utfm.aeadtfm = aeadtfm;
		}
	} else {
		aeadtfm  = NULL;
		ahashtfm = crypto_alloc_ahash(alg_name, 0, 0);
		if (IS_ERR(ahashtfm))
			goto error;
		ahp->utfm.atfm = ahashtfm;
	}

	if (x->alg_flags & XFRM_ALGO_FLAGS_OFFLOAD_AH) {
		/* For AH offload, we must load AH offload parameters
		   via setkey function. */
		key_len = RTA_SPACE(sizeof(*param)) +
        		  ((x->aalg->alg_key_len + 7) / 8);
		key = kmalloc(key_len, GFP_KERNEL);
		rta = (void *) key;
		rta->rta_type = CRYPTO_AUTHENC_KEYA_PARAM;
		rta->rta_len  = RTA_LENGTH(sizeof(*param));
		param = RTA_DATA(rta);
		param->spi = cpu_to_be32(x->id.spi);
		param->seq = cpu_to_be32(x->replay.oseq);
		memcpy(key + RTA_SPACE(sizeof(*param)),
		       x->aalg->alg_key,
		       (x->aalg->alg_key_len + 7) / 8);
		if (crypto_aead_setkey(aeadtfm, key, key_len))
			goto error;
		digest_size = crypto_aead_tfm(aeadtfm)->__crt_alg->
					cra_aead.maxauthsize;
	} else {
		key_len = (x->aalg->alg_key_len + 7) / 8;
		key     = x->aalg->alg_key;
		if (crypto_ahash_setkey(ahashtfm, key, key_len))
			goto error;
		digest_size = crypto_ahash_digestsize(ahashtfm);
	}

	/*
	 * Lookup the algorithm description maintained by xfrm_algo,
	 * verify crypto transform properties, and store information
	 * we need for AH processing.  This lookup cannot fail here
	 * after a successful crypto_alloc_ahash().
	 */
	aalg_desc = xfrm_aalg_get_byname(x->aalg->alg_name, 0);
	BUG_ON(!aalg_desc);

	if (aalg_desc->uinfo.auth.icv_fullbits/8 != digest_size) {
		printk(KERN_INFO "AH: %s digestsize %u != %hu\n",
		       x->aalg->alg_name, digest_size,
		       aalg_desc->uinfo.auth.icv_fullbits/8);
		goto error;
	}

	ahp->icv_full_len = aalg_desc->uinfo.auth.icv_fullbits/8;
	ahp->icv_trunc_len = aalg_desc->uinfo.auth.icv_truncbits/8;
	BUG_ON(ahp->icv_trunc_len > MAX_AH_AUTH_LEN);

	/* For AH hardware offload, set ICV size */
	if (aeadtfm)
		crypto_aead_setauthsize(aeadtfm, ahp->icv_trunc_len);

	x->props.header_len = XFRM_ALIGN8(sizeof(struct ip_auth_hdr) +
					  ahp->icv_trunc_len);
	if (x->props.mode == XFRM_MODE_TUNNEL)
		x->props.header_len += sizeof(struct iphdr);
	x->data = ahp;

	return 0;

error:
	if (ahp) {
		crypto_free_ahash(ahp->utfm.atfm);
		kfree(ahp);
	}
	return -EINVAL;
}

static void ah_destroy(struct xfrm_state *x)
{
	struct ah_data *ahp = x->data;

	if (!ahp)
		return;

	crypto_free_ahash(ahp->utfm.atfm);
	ahp->utfm.atfm = NULL;
	kfree(ahp);
}

static const struct xfrm_type ah_type =
{
	.description	= "AH4",
	.owner		= THIS_MODULE,
	.proto	     	= IPPROTO_AH,
	.flags		= XFRM_TYPE_REPLAY_PROT,
	.init_state	= ah_init_state,
	.destructor	= ah_destroy,
	.input		= ah_input,
	.output		= ah_output
};

static const struct net_protocol ah4_protocol = {
	.handler	=	xfrm4_rcv,
	.err_handler	=	ah4_err,
	.no_policy	=	1,
	.netns_ok	=	1,
};

static int __init ah4_init(void)
{
	if (xfrm_register_type(&ah_type, AF_INET) < 0) {
		printk(KERN_INFO "ip ah init: can't add xfrm type\n");
		return -EAGAIN;
	}
	if (inet_add_protocol(&ah4_protocol, IPPROTO_AH) < 0) {
		printk(KERN_INFO "ip ah init: can't add protocol\n");
		xfrm_unregister_type(&ah_type, AF_INET);
		return -EAGAIN;
	}
	return 0;
}

static void __exit ah4_fini(void)
{
	if (inet_del_protocol(&ah4_protocol, IPPROTO_AH) < 0)
		printk(KERN_INFO "ip ah close: can't remove protocol\n");
	if (xfrm_unregister_type(&ah_type, AF_INET) < 0)
		printk(KERN_INFO "ip ah close: can't remove xfrm type\n");
}

module_init(ah4_init);
module_exit(ah4_fini);
MODULE_LICENSE("GPL");
MODULE_ALIAS_XFRM_TYPE(AF_INET, XFRM_PROTO_AH);
