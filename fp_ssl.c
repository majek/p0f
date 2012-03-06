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


int fingerprint_ssl_v2(struct ssl_sig *sig, const u8 *pay, u32 pay_len) {

  const u8 *pay_end = pay + pay_len;
  const u8 *tmp_end;

  if (pay + sizeof(struct ssl2_hdr) > pay_end) goto abort_message;

  struct ssl2_hdr *hdr = (struct ssl2_hdr*)pay;
  pay += sizeof(struct ssl2_hdr);


  /* SSLv2 has version 0x0002 on the wire. */
  if (hdr->ver_min == 2 && hdr->ver_maj == 0) {

    sig->request_version = 0x0200;

  } else {

    sig->request_version = (hdr->ver_maj << 8) | hdr->ver_min;

  }


  u16 cipher_spec_len = ntohs(hdr->cipher_spec_length);

  if (cipher_spec_len % 3) {

    DEBUG("[#] SSLv2 cipher_spec_len=%u is not divisable by 3.\n",
          cipher_spec_len);
    return -1;

  }

  if (pay + cipher_spec_len > pay_end) goto abort_message;

  sig->cipher_suites = ck_alloc((cipher_spec_len / 3) * sizeof(u32));
  sig->cipher_suites_len = 0;
  tmp_end = pay + cipher_spec_len;

  while (pay < tmp_end) {

    sig->cipher_suites[sig->cipher_suites_len++] =
      (pay[0] << 16) | (pay[1] << 8) | pay[2];
    pay += 3;

  }


  u16 session_id_len = ntohs(hdr->session_id_length);
  u16 challenge_len = ntohs(hdr->challenge_length);

  if (pay + session_id_len + challenge_len > pay_end) goto stop;
  pay += session_id_len + challenge_len;

  if (pay != pay_end) {

    DEBUG("[#] SSLv2 extra %u bytes remaining after client-hello message.\n",
          pay_end - pay);

  }


stop:

  return 1;


abort_message:

  ck_free(sig->cipher_suites);

  return -1;

}

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

    DEBUG("[#] SSL cipher_suites_len=%u is not even.\n", cipher_suites_len);
    goto abort_message;

  }

  if (pay + cipher_suites_len > pay_end)
    goto abort_message;

  sig->cipher_suites = ck_alloc((cipher_suites_len / 2) * sizeof(u32));
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

  sig->compression_methods = ck_alloc(compression_methods_len);
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

  sig->extensions = ck_alloc(extensions_len);
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

  DEBUG("[#] SSL %i.%i;", sig->request_version >> 8, sig->request_version & 0xFF);
  int i;

  for (i=0; i < sig->cipher_suites_len; i++)
    DEBUG("%s%x", (!i ? "" : ","), sig->cipher_suites[i]);

  DEBUG(";");

  for (i=0; i < sig->extensions_len; i++) {
    u32 ext = sig->extensions[i];
    DEBUG("%s%s%x", (!i ? "" : ","),
          (ext == 0 || ext == 5 ? "?" : ""),
          ext);
  }

  DEBUG(";");

  int j=0;
  if (sig->record_version == 0x0200) {
    DEBUG("%sv2", (!j++ ? "" : ","));
  } else {
    if (sig->record_version != sig->request_version)
      DEBUG("%sver", (!j++ ? "" : ","));
  }

  for (i=0; i < sig->compression_methods_len; i++) {
    if (sig->compression_methods[i] == 1) {
      DEBUG("%scompr", (!j++ ? "" : ","));
      break;
    }
  }

  DEBUG("\n");

}


/* Examine request or response; returns 1 if more data needed and plausibly can
   be read. Note that the buffer is always NUL-terminated. */

u8 process_ssl(u8 to_srv, struct packet_flow *f) {

  int success = 0;
  struct ssl_sig sig;


  /* Already decided this flow? */

  if (f->in_ssl) return 0;


  /* Tracking requests only. */

  if (!to_srv) return 0;


  u8 can_get_more = (f->req_len < MAX_FLOW_DATA);


  /* SSLv3 record is 5 bytes, message is 4 + 38; SSLv2 CLIENT-HELLO is
     11 bytes - we try to recognize protocol by looking at top 6
     bytes. */

  if (f->req_len < 6) return can_get_more;

  struct ssl2_hdr *hdr2 = (struct ssl2_hdr*)f->request;
  u16 msg_length = ntohs(hdr2->msg_length);

  struct ssl3_record_hdr *hdr3 = (struct ssl3_record_hdr*)f->request;
  u16 fragment_len = ntohs(hdr3->length);


  /* Does it look like top 5 bytes of SSLv2? Most significant bit must
     be set, followed by 15 bits indicating record length, which must
     be at least 9. */

  if ((msg_length & 0x8000) &&
      (msg_length & ~0x8000) >= sizeof(struct ssl2_hdr) - 2 &&
      hdr2->msg_type == 1 &&
      ((hdr2->ver_maj == 3 && hdr2->ver_min < 4) ||
       (hdr2->ver_min == 2 && hdr2->ver_maj == 0))) {

    /* Clear top bit. */
    msg_length &= ~0x8000;

    if (f->req_len < 2 + msg_length) return can_get_more;

    memset(&sig, 0, sizeof(struct ssl_sig));
    sig.record_version = 0x0200;

    success = fingerprint_ssl_v2(&sig, f->request, msg_length + 2);

  }


  /* Top 5 bytes of SSLv3/TLS header? Currently available TLS
     versions: 3.0 - 3.3. The rfc disallows fragment to have more than
     2^14 bytes. Also length less than 4 bytes doesn't make much
     sense. Additionally let's peek the meesage type. */

  else if (hdr3->content_type == SSL3_REC_HANDSHAKE &&
           hdr3->ver_maj == 3 && hdr3->ver_min < 4 &&
           fragment_len > 3 && fragment_len < (1 << 14) &&
           f->request[5] == SSL3_MSG_CLIENT_HELLO) {

    if (f->req_len < sizeof(struct ssl3_record_hdr) + fragment_len)
      return can_get_more;

    memset(&sig, 0, sizeof(struct ssl_sig));
    sig.record_version = (hdr3->ver_maj << 8) | hdr3->ver_min;
    sig.local_time = f->client->last_seen;

    u8 *fragment = f->request + sizeof(struct ssl3_record_hdr);

    success = fingerprint_ssl_v3(&sig, fragment, fragment_len);

  }

  if (success != 1) {

    DEBUG("[#] Does not look like SSLv2 nor SSLv3.\n");

    f->in_ssl = -1;
    return 0;

  }

  print_ssl_sig(&sig);

  ck_free(sig.cipher_suites);
  ck_free(sig.compression_methods);
  ck_free(sig.extensions);

  f->in_ssl = 1;
  return 0;

}
