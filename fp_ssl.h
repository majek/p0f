/*
   p0f - SSL fingerprinting
   -------------------------

   Copyright (C) 2012 by Marek Majkowski <marek@popcnt.org>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef _HAVE_FP_SSL_H
#define _HAVE_FP_SSL_H

#include "types.h"

#define SSL3_REC_HANDSHAKE 0x16    /* 22 */

struct ssl3_record_hdr {

  u8 content_type;
  u8 ver_maj;
  u8 ver_min;
  u16 length;

} __attribute__((packed));


#define SSL3_MSG_CLIENT_HELLO 0x01

#define SSL3_MSG_CLIENT_HELLO_MIN_SZ 38


struct ssl2_hdr {

  u16 msg_length;
  u8 msg_type;
  u8 ver_maj;
  u8 ver_min;

  u16 cipher_spec_length;
  u16 session_id_length;
  u16 challenge_length;

} __attribute__((packed));

#define SSL2_CLIENT_HELLO_MIN_SZ 11

struct ssl_message_hdr {

  u8 message_type;
  u8 length[3];

} __attribute__((packed));


struct ssl_sig {

  u16 record_version;           /* TLS version used on the record layer.  */
  u16 request_version;          /* Requested SSL version (maj << 8) | min */

  u32 remote_time;              /* ClientHello message gmt_unix_time field */
  u32 local_time;               /* Receive time. */

  u32 *cipher_suites;
  u32 cipher_suites_len;

  u8 *compression_methods;
  u32 compression_methods_len;

  u16 *extensions;
  u32 extensions_len;

};

u8 process_ssl(u8 to_srv, struct packet_flow* f);

#endif /* _HAVE_FP_SSL_H */
