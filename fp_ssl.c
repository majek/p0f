/*
  p0f - SSL fingerprinting
  -------------------------

  Copyright (C) 2012 by Marek Majkowski <marek@popcnt.org>

  Distributed under the terms and conditions of GNU LGPL.


*/

#define _FROM_FP_SSL
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>

#include <netinet/in.h>
#include <sys/types.h>

#include "types.h"
#include "config.h"
#include "debug.h"
#include "alloc-inl.h"
#include "process.h"
#include "readfp.h"
#include "p0f.h"
#include "tcp.h"
#include "hash.h"

#include "fp_ssl.h"


/* Unpack SSLv3 fragment to a signature. We expect to hear ClientHello
 message.  -1 on parsing error, 1 if signature was extracted. */

int fingerprint_ssl_v3(struct ssl_sig *sig, const u8 *fragment, u32 frag_len) {

  const u8 *record = fragment;
  const u8 *frag_end = fragment + frag_len;

  struct ssl_message_hdr *msg = (struct ssl_message_hdr*)record;
  u32 msg_len = (msg->length[0] << 16) |
                (msg->length[1] << 8) |
                (msg->length[2]);

  const u8 *pay = (const u8*)msg + sizeof(struct ssl_message_hdr);
  const u8 *pay_end = pay + msg_len;
  const u8 *tmp_end;

  /* Roll on pointer to next record. */

  record += msg_len + sizeof(struct ssl_message_hdr);


  /* Record size goes beyond current fragment - that's fine by SSL */

  if (record > frag_end) {

    DEBUG("[#] SSL Fragment coalescing not supported - %u bytes requested.\n",
          record - frag_end);

    return -1;

  }

  if (msg->message_type != SSL3_MSG_CLIENT_HELLO) {

    /* Rfc526 says: The handshake protocol messages are presented
         below in the order they MUST be sent; sending handshake
         messages in an unexpected order results in a fatal error.

       I guess we can assume that the first frame is ClientHello.
    */

    DEBUG("[#] SSL First message type 0x%02x (%u bytes) not supported.\n",
          msg->message_type, msg_len);
    return -1;

  }


  /* ClientHello */


  /* Header (34B) + session_id_len (1B) */

  if (pay + 2 + 4 + 28 + 1 > pay_end) goto abort_message;

  sig->request_version = (pay[0] << 8) | pay[1];

  sig->remote_time = ntohl(*((u32*)&pay[2]));


  /* Skip random, ignore session_id */

  u8 session_id_len = pay[34];
  pay += 35;

  if (pay + session_id_len + 2 > pay_end) goto abort_message;

  pay += session_id_len;


  /* Cipher suites */

  u16 cipher_suites_len = (pay[0] << 8) | pay[1];
  pay += 2;

  if (cipher_suites_len % 2) {

    DEBUG("[.] SSL cipher_suites_len=%u is not even.\n", cipher_suites_len);
    goto abort_message;

  }

  if (pay + cipher_suites_len > pay_end)
    goto abort_message;

  sig->cipher_suites = (u16*)ck_alloc(cipher_suites_len);
  sig->cipher_suites_len = 0;
  tmp_end = pay + cipher_suites_len;

  while (pay < tmp_end) {

    sig->cipher_suites[sig->cipher_suites_len++] = (pay[0] << 8) | pay[1];
    pay += 2;

  }

  if (pay + 1 > pay_end ) goto stop;

  u8 compression_methods_len = pay[0];
  pay += 1;

  if (pay + compression_methods_len > pay_end ) goto stop;

  sig->compression_methods = (u8*)ck_alloc(compression_methods_len);
  sig->compression_methods_len = 0;
  tmp_end = pay + compression_methods_len;

  while (pay < tmp_end) {

    sig->compression_methods[sig->compression_methods_len++] = pay[0];
    pay += 1;

  }

  if (pay + 2 > pay_end) goto stop;

  u16 extensions_len = (pay[0] << 8) | pay[1];
  pay += 2;

  if (pay + extensions_len > pay_end) goto stop;

  sig->extensions = (u16*)ck_alloc(extensions_len);
  sig->extensions_len = 0;
  tmp_end = pay + extensions_len;

  while (pay < tmp_end) {

    u16 ext_type = (pay[0] << 8) | pay[1];
    u16 ext_len = (pay[2] << 8) | pay[3];
    const u8 *extension = &pay[4];
    pay += 4 + ext_len;

    if (pay > tmp_end) goto stop;

    sig->extensions[sig->extensions_len++] = ext_type;

    /* Ignore the actual value of the extenstion. */
    extension = extension;
  }

  if (pay != pay_end) {

    DEBUG("[#] SSL ClientHello remaining %i bytes after extensions.\n",
          pay_end - pay);

  }

  if (record != frag_end) {

    DEBUG("[#] SSL %i bytes remaining after ClientHello message.\n",
          frag_end - record);

  }

stop:

  return 1;


abort_message:

  DEBUG("[#] SSL Packet malformed.\n");

  ck_free(sig->cipher_suites);
  ck_free(sig->compression_methods);
  ck_free(sig->extensions);

  return -1;

}


void print_ssl_sig(struct ssl_sig *sig) {

  DEBUG("[#] SSL %04x;%04x;", sig->record_version, sig->request_version);
  int i;

  for (i=0; i < sig->cipher_suites_len; i++)
    DEBUG("%s%x", (!i ? "" : ","), sig->cipher_suites[i]);

  DEBUG(";");

  for (i=0; i < sig->compression_methods_len; i++)
    DEBUG("%s%x", (!i ? "" : ","), sig->compression_methods[i]);

  DEBUG(";");

  for (i=0; i < sig->extensions_len; i++)
    DEBUG("%s%x", (!i ? "" : ","), sig->extensions[i]);

  DEBUG(";%u\n", sig->local_time - sig->remote_time);

}


/* Examine request or response; returns 1 if more data needed and plausibly can
   be read. Note that the buffer is always NUL-terminated. */

u8 process_ssl(u8 to_srv, struct packet_flow *f) {

  /* Already decided this flow? */

  if (f->in_ssl) return 0;


  /* Tracking requests only. */

  if (!to_srv) return 0;


  u8 can_get_more = (f->req_len < MAX_FLOW_DATA);

  if (f->req_len < sizeof(struct ssl3_record_hdr)) return can_get_more;

  struct ssl3_record_hdr *hdr = (struct ssl3_record_hdr*)f->request;
  u16 fragment_len = ntohs(hdr->length);

  /* Currently available TLS versions: 3.0, 3.1, 3.2, 3.3. The rfc
     disallows fragment to have more than 2^14 bytes. Also length less
     than 4 bytes doesn't make much sense. */

  if (hdr->content_type != SSL3_REC_HANDSHAKE ||
      hdr->ver_maj != 3 ||
      hdr->ver_min > 3 || fragment_len > (1 << 14) || fragment_len < 4) {

    DEBUG("[#] Does not look like SSLv3\n");

    f->in_ssl = -1;
    return 0;

  }

  if (f->req_len < sizeof(struct ssl3_record_hdr) + fragment_len)
    return can_get_more;


  struct ssl_sig *sig = (struct ssl_sig*)ck_alloc(sizeof(struct ssl_sig));

  sig->record_version = (hdr->ver_maj << 8) | hdr->ver_min;
  sig->local_time = f->client->last_seen;

  u8 *fragment = f->request + sizeof(struct ssl3_record_hdr);


  if (fingerprint_ssl_v3(sig, fragment, fragment_len) == 1) {

    print_ssl_sig(sig);

    f->in_ssl = 1;

    ck_free(sig->cipher_suites);
    ck_free(sig->compression_methods);
    ck_free(sig->extensions);

  }

  ck_free(sig);

  f->in_ssl = 0;
  return 0;

}


