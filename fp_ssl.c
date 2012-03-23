/* -*-mode:c; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
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


static struct ssl_sig_record* sigs[2];
static u32 sig_cnt[2];


static u32* load_sig(char** val_ptr) {
  char *val = *val_ptr;
  u32 ciphers[128];
  u8 p = 0;
  while (p < 128) {
    u32 optional = 0;
    if (*val == '*') {
      ciphers[p++] = MATCH_ANY;
      val ++;
    } else {
      char *pval = val;
      if (*val == '?') {optional = MATCH_MAYBE; val ++;}
      ciphers[p] = strtol(val, &val, 16) | optional;
      if (val != pval) p++;
    }
    if (*val != ':' && *val != ',') return NULL;
    if (*val == ':') break;
    val ++; // ,
  }

  *val_ptr = val;
  u32* ret = DFL_ck_alloc((p + 1) * sizeof(u32));
  memcpy(ret, ciphers, p * sizeof(u32));
  ret[p] = END_MARKER;
  return ret;

}


void ssl_register_sig(u8 to_srv, u8 generic, s32 sig_class, u32 sig_name,
                       u8* sig_flavor, u32 label_id, u32* sys, u32 sys_cnt,
                       u8* uval, u32 line_no) {

  struct ssl_sig* ssig;
  struct ssl_sig_record* srec;

  char *val = (char*)uval;
  ssig = DFL_ck_alloc(sizeof(struct ssl_sig));

  sigs[to_srv] = DFL_ck_realloc(sigs[to_srv], sizeof(struct ssl_sig_record) *
                                (sig_cnt[to_srv] + 1));

  srec = &sigs[to_srv][sig_cnt[to_srv]];


  int maj = strtol(val, &val, 10);
  if (!val || *val != '.')  FATAL("Malformed signature in line %u.", line_no);
  val ++;
  int min = strtol(val, &val, 10);
  if (!val || *val != ':')  FATAL("Malformed signature in line %u.", line_no);
  val ++;

  ssig->request_version = (maj << 8) | min;

  ssig->cipher_suites = load_sig(&val);
  if (!val || *val != ':' || !ssig->cipher_suites) FATAL("Malformed signature in line %u %c.", line_no, *val);
  val ++;

  ssig->extensions = load_sig(&val);
  if (!val || *val != ':' || !ssig->extensions) FATAL("Malformed signature in line %u %c.", line_no, *val);
  val ++;


  while (*val) {

    if (!strncmp((char*)val, "compr", 5)) {

      ssig->flags |= SSL_FLAG_COMPR;
      val += 5;

    } else if (!strncmp((char*)val, "v2", 2)) {

      ssig->flags |= SSL_FLAG_V2;
      val += 2;

    } else if (!strncmp((char*)val, "ver", 3)) {

      ssig->flags |= SSL_FLAG_VER;
      val += 3;

    } else if (!strncmp((char*)val, "rand", 4)) {

      ssig->flags |= SSL_FLAG_RAND;
      val += 4;

    } else if (!strncmp((char*)val, "time", 4)) {

      ssig->flags |= SSL_FLAG_TIME;
      val += 4;

    } else if (!strncmp((char*)val, "stime", 5)) {

      ssig->flags |= SSL_FLAG_STIME;
      val += 5;

    } else {

      FATAL("Unrecognized flag in line %u.", line_no);

    }

    if (*val == ',') val++;

  }


  srec->class_id = sig_class;
  srec->name_id  = sig_name;
  srec->flavor   = sig_flavor;
  srec->label_id = label_id;
  srec->sys      = sys;
  srec->sys_cnt  = sys_cnt;
  srec->line_no  = line_no;
  srec->generic  = generic;

  srec->sig      = ssig;

  sig_cnt[to_srv]++;

}


static int match_sigs(u32* x, u32* c) {
  u32 *r = x;
  u32 *c2;
  u8 match_any = 0;

  for (; *r != END_MARKER && *c != END_MARKER; r++) {
    if (*r == *c || (*r & ~MATCH_MAYBE) == *c) {
      /* Exact match, move on */
      match_any = 0; c++;
      continue;
    }

    if (*r == MATCH_ANY) {
      /* Star, may match anything */
      match_any = 1;
      continue;
    }

    if (*r & MATCH_MAYBE) {
      /* Optional match */
      if (!match_any) {
        /* not fulfilled */
        continue;
      } else {
        for (c2 = c; *c2 != END_MARKER; c2++) {
          if (*c2 == (*r & ~MATCH_MAYBE)) {
            /* Match */
            c = c2 + 1;
            break;
          }
        }
        /* No optional match (or match if from broken for) */
        match_any = 0;
        continue;
      }
    }

    if (match_any) {
      for (; *c != END_MARKER; c++) {
        if (*r == *c) {
          c++;
          break;
        }
      }
      match_any = 0;
      continue;
    }

    return 1;
  }

  while (*r != END_MARKER) {
    if ((*r & MATCH_MAYBE) || *r == MATCH_ANY) {
      r ++;
    } else {
      break;
    }
  }

  if (*r == END_MARKER && *c == END_MARKER)
    return 0;

  if (*r == END_MARKER && match_any)
    return 0;


  return 1;
}


static void ssl_find_match(u8 to_srv, struct ssl_sig* ts, u8 dupe_det) {

  u32 i;

  for (i = 0; i < sig_cnt[to_srv]; i++) {

    struct ssl_sig_record* ref = sigs[to_srv] + i;
    struct ssl_sig* rs = CP(ref->sig);

    /* Exact version match. */
    if (rs->request_version != ts->request_version) continue;

    /* At least flags from the record. */
    if ((rs->flags & ts->flags) != rs->flags) continue;

    /* Extensions match. */
    int extensions_match = match_sigs(rs->extensions, ts->extensions);
    if (extensions_match != 0) continue;

    /* Cipher suites match. */
    int suites_match = match_sigs(rs->cipher_suites, ts->cipher_suites);
    if (suites_match != 0) continue;

    ts->matched = ref;
    return;

  }

}


static int fingerprint_ssl_v2(struct ssl_sig *sig, const u8 *pay, u32 pay_len) {

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

  int cipher_pos = 0;
  sig->cipher_suites = ck_alloc(((cipher_spec_len / 3) + 1) * sizeof(u32));
  tmp_end = pay + cipher_spec_len;

  while (pay < tmp_end) {

    sig->cipher_suites[cipher_pos++] =
      (pay[0] << 16) | (pay[1] << 8) | pay[2];
    pay += 3;

  }
  sig->cipher_suites[cipher_pos] = END_MARKER;


  u16 session_id_len = ntohs(hdr->session_id_length);
  u16 challenge_len = ntohs(hdr->challenge_length);

  if (pay + session_id_len + challenge_len > pay_end) goto stop;
  pay += session_id_len + challenge_len;

  if (pay != pay_end) {

    DEBUG("[#] SSLv2 extra %u bytes remaining after client-hello message.\n",
          pay_end - pay);

  }


stop:

  sig->extensions    = ck_alloc(1 * sizeof(u32));
  sig->extensions[0] = END_MARKER;

  return 1;


abort_message:

  ck_free(sig->cipher_suites);
  ck_free(sig->extensions);

  return -1;

}

/* Unpack SSLv3 fragment to a signature. We expect to hear ClientHello
 message.  -1 on parsing error, 1 if signature was extracted. */

static int fingerprint_ssl_v3(struct ssl_sig *sig, const u8 *fragment,
                              u32 frag_len, u32 local_time) {

  int i;
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

  if (sig->request_version != sig->record_version) {
    sig->flags |= SSL_FLAG_VER;
  }

  sig->remote_time = ntohl(*((u32*)&pay[2]));
  sig->local_time  = local_time;
  s32 delta = abs((s32)(sig->local_time - sig->remote_time));

  if (sig->remote_time < 1*365*24*60*60) {

    /* Old Firefox on windows uses */
    sig->flags |= SSL_FLAG_STIME;

  } else if (delta > 5*365*24*60*60) {

    /* More than 5 years difference? */
    sig->flags |= SSL_FLAG_TIME;

    DEBUG("[#] SSL timer looks wrong: delta=%i remote_time=%08x\n",
          delta, sig->remote_time);

  }


  pay += 6;


  /* Random */
  u16 *random = (u16*)pay;
  pay += 28;

  for (i=0; i<14; i++) {
    if (random[i] == 0x0000 || random[i] == 0xffff) {
      sig->flags |= SSL_FLAG_RAND;
    }
  }

  /* Skip session_id */
  u8 session_id_len = pay[0];
  pay += 1;

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

  int cipher_pos = 0;
  sig->cipher_suites = ck_alloc(((cipher_suites_len / 2) + 1) * sizeof(u32));
  tmp_end = pay + cipher_suites_len;

  while (pay < tmp_end) {

    sig->cipher_suites[cipher_pos++] = (pay[0] << 8) | pay[1];
    pay += 2;

  }
  sig->cipher_suites[cipher_pos] = END_MARKER;

  if (pay + 1 > pay_end ) goto stop;

  u8 compression_methods_len = pay[0];
  pay += 1;

  if (pay + compression_methods_len > pay_end ) goto stop;

  tmp_end = pay + compression_methods_len;

  while (pay < tmp_end) {

    if (pay[0] == 1) {
      sig->flags |= SSL_FLAG_COMPR;
    }

    pay += 1;

  }

  if (pay + 2 > pay_end) goto stop;

  u16 extensions_len = (pay[0] << 8) | pay[1];
  pay += 2;

  if (pay + extensions_len > pay_end) goto stop;

  int extensions_pos = 0;
  sig->extensions = ck_alloc(((extensions_len / 4) + 1) * sizeof(u32));
  tmp_end = pay + extensions_len;

  while (pay + 4 <= tmp_end) {

    u16 ext_type = (pay[0] << 8) | pay[1];
    u16 ext_len  = (pay[2] << 8) | pay[3];
    const u8 *extension = &pay[4];
    pay += 4;

    pay += ext_len;

    sig->extensions[extensions_pos++] = ext_type;

    /* Extension payload sane? */
    if (pay > tmp_end) break;

    /* Ignore the actual value of the extenstion. */
    extension = extension;
  }

  /* Make sure the terminator is always appended, even if extensions
     are malformed. */
  sig->extensions = ck_realloc(sig->extensions, (extensions_pos + 1) *
                               sizeof(u32));
  sig->extensions[extensions_pos] = END_MARKER;

  if (pay != tmp_end) {

    DEBUG("[#] SSL malformed extensions, %i bytes over.\n",
          pay - tmp_end);
    goto stop;

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

  if (!sig->extensions) {
    sig->extensions    = ck_alloc(1*sizeof(u32));
    sig->extensions[0] = END_MARKER;
  }

  return 1;


abort_message:

  DEBUG("[#] SSL Packet malformed.\n");

  ck_free(sig->cipher_suites);
  ck_free(sig->extensions);

  return -1;

}


static u8* dump_sig(struct ssl_sig *sig) {

  int i, had_prev;

  static u8* ret;
  u32 rlen = 0;

#define RETF(_par...) do { \
    s32 _len = snprintf(NULL, 0, _par); \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    ret = DFL_ck_realloc_kb(ret, rlen + _len + 1); \
    snprintf((char*)ret + rlen, _len + 1, _par); \
    rlen += _len; \
  } while (0)

  /* RETF("%u:", sig->local_time); */
  RETF("%i.%i:", sig->request_version >> 8, sig->request_version & 0xFF);

  for (i=0; sig->cipher_suites[i] != END_MARKER; i++) {
    u32 c = sig->cipher_suites[i];
    if (c != MATCH_ANY) {
      RETF("%s%s%x", (!i ? "" : ","),
           (c & MATCH_MAYBE) ? "?" : "",
           c & ~MATCH_MAYBE);
    } else {
      RETF("%s*", (!i ? "" : ","));
    }
  }

  RETF(":");

  for (i=0; sig->extensions[i] != END_MARKER; i++) {
    u32 ext = sig->extensions[i];
    if (ext != MATCH_ANY) {
      RETF("%s%s%x", (!i ? "" : ","),
           ((ext & MATCH_MAYBE) || ext == 0 ? "?" : ""),
           ext & ~MATCH_MAYBE);
    } else {
      RETF("%s*", (!i ? "" : ","));
    }
  }

  RETF(":");
  had_prev = 0;

  if (sig->flags & SSL_FLAG_COMPR) {
    RETF("%scompr", had_prev ? "," : "");
    had_prev = 1;
  }

  if (sig->flags & SSL_FLAG_V2) {
    RETF("%sv2", had_prev ? "," : "");
    had_prev = 1;
  }

  if (sig->flags & SSL_FLAG_VER) {
    RETF("%sver", had_prev ? "," : "");
    had_prev = 1;
  }

  if (sig->flags & SSL_FLAG_RAND) {
    RETF("%srand", had_prev ? "," : "");
    had_prev = 1;
  }

  if (sig->flags & SSL_FLAG_TIME) {
    RETF("%stime", had_prev ? "," : "");
    had_prev = 1;
  }

  if (sig->flags & SSL_FLAG_STIME) {
    RETF("%sstime", had_prev ? "," : "");
    had_prev = 1;
  }


  /* RETF(":%x", sig->remote_time); */

  return ret;

}


static void fingerprint_ssl(u8 to_srv, struct packet_flow* f, struct ssl_sig *sig) {

  struct ssl_sig_record* m;
  ssl_find_match(to_srv, sig, 0);

  start_observation("ssl request", 4, to_srv, f);

  if ((m = sig->matched)) {

    OBSERVF((m->class_id < 0) ? "app" : "os", "%s%s%s",
            fp_os_names[m->name_id], m->flavor ? " " : "",
            m->flavor ? m->flavor : (u8*)"");

    add_observation_field("match_sig", dump_sig(sig->matched->sig));
  } else {
    add_observation_field("app", NULL);
    add_observation_field("match_sig", NULL);
  }

  if ((sig->flags & (SSL_FLAG_TIME | SSL_FLAG_STIME)) == 0) {

    OBSERVF("drift", "%i", abs(sig->remote_time - sig->local_time));

  } else add_observation_field("drift", NULL);

// if stime - time from reboot (ff 2.0)

  add_observation_field("raw_sig", dump_sig(sig));

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
    sig.flags |= SSL_FLAG_V2;

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

    u8 *fragment = f->request + sizeof(struct ssl3_record_hdr);

    success = fingerprint_ssl_v3(&sig, fragment, fragment_len,
                                 f->client->last_seen);

  }

  if (success != 1) {

    DEBUG("[#] Does not look like SSLv2 nor SSLv3.\n");

    f->in_ssl = -1;
    return 0;

  }


  long a = f->client->last_seen;
  struct tm *tm = gmtime(&a);
  char buf[512];

  strftime(buf, sizeof(buf), "%d/%b/%Y:%T %z", tm);

  DEBUG("%s - - [%s] ", addr_to_str(f->client->addr, f->client->ip_ver), buf);

  f->in_ssl = 1;

  fingerprint_ssl(to_srv, f, &sig);

  ck_free(sig.cipher_suites);
  ck_free(sig.extensions);

  return 0;

}
