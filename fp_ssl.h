/* -*-mode:c; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
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


struct ssl_sig_record;

struct ssl_sig {

  u16 request_version;          /* Requested SSL version (maj << 8) | min */

  u32 remote_time;              /* ClientHello message gmt_unix_time field */
  u32 local_time;               /* Receive time. */

  u32 *cipher_suites;

  u32 *extensions;

  u32 flags;

  struct ssl_sig_record* matched; /* NULL = no match */
};

#define SSL_FLAG_V2    0x0001  /* SSLv2 handshake. */
#define SSL_FLAG_VER   0x0002  /* Record version different than ClientHello. */
#define SSL_FLAG_RAND  0x0004  /* 0xffff or 0x0000 detected in random. */
#define SSL_FLAG_TIME  0x0008  /* weird SSL time, (delta > 5 years), most likely random*/
#define SSL_FLAG_STIME 0x0010  /* small SSL time, (absolute value < 1 year)
                                  most likely time since reboot for old ff */
#define SSL_FLAG_COMPR 0x0020  /* Deflate compression supported. */

struct ssl_sig_record {

  s32 class_id;                         /* OS class ID (-1 = user)            */
  s32 name_id;                          /* OS name ID                         */
  u8* flavor;                           /* Human-readable flavor string       */

  u32 label_id;                         /* Signature label ID                 */

  u32* sys;                             /* OS class / name IDs for user apps  */
  u32  sys_cnt;                         /* Length of sys                      */

  u32  line_no;                         /* Line number in p0f.fp              */

  u8 generic;                           /* Generic signature?                 */

  struct ssl_sig* sig;                  /* Actual signature data              */

};

void ssl_register_sig(u8 to_srv, u8 generic, s32 sig_class, u32 sig_name,
                       u8* sig_flavor, u32 label_id, u32* sys, u32 sys_cnt,
		      u8* val, u32 line_no);

u8 process_ssl(u8 to_srv, struct packet_flow* f);


#define MATCH_MAYBE 0x10000000
#define MATCH_ANY   0x20000000
#define END_MARKER  0xFF000000

#endif /* _HAVE_FP_SSL_H */
