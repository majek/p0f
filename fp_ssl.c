/* -*-mode:c; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
  p0f - SSL fingerprinting
  -------------------------

  Copyright (C) 2012 by Marek Majkowski <marek@popcount.org>

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

/* Flags for SSL signaturs */
struct flag {
  char* name;
  int name_len;
  u32 value;
};

struct flag flags[] = {{"compr", 5, SSL_FLAG_COMPR},
                       {"v2",    2, SSL_FLAG_V2},
                       {"ver",   3, SSL_FLAG_VER},
                       {"rtime", 5, SSL_FLAG_RTIME},
                       {"stime", 5, SSL_FLAG_STIME},
                       {"rand",  4, SSL_FLAG_RAND},
                       {"chlen", 5, SSL_FLAG_CHLEN},
                       {NULL, 0, 0}};


/* Signatures are stored as flat list. Matching is fast: ssl version
   and flags must match exactly, matching ciphers and extensions
   usually require looking only at a first few bytes of the
   signature. Assuming the signature doesn't start with a star. */

static struct ssl_sig_record* signatures;
static u32 signatures_cnt;


/* Decode a string of comma separated hex numbers into an annotated
   u32 array. Exit with success on '\0' or ':'. */

static u32* decode_hex_string(const u8** val_ptr, u32 line_no) {

  const u8* val = *val_ptr;

  u32 rec[SSL_MAX_CIPHERS];
  u8 p = 0;

  while (p < SSL_MAX_CIPHERS) {

    u32 optional = 0;
    const u8* prev_val;
    u32* ret;

    /* State #1: expecting value */

    switch (*val) {

    case '*':
      rec[p++] = MATCH_ANY;
      val ++;
      break;

    case '?':
      optional = MATCH_MAYBE;
      val ++;
      /* Must be a hex digit after question mark */
    case 'a' ... 'f':
    case '0' ... '9':
      prev_val = val;
      rec[p++] = (strtol((char*)val, (char**)&val, 16) & 0xFFFFFF) | optional;
      if (val == prev_val) return NULL;
      break;

    default:
      /* Support empty list - jump to second state. */
      if (p == 0)
        break;

      return NULL;

    }

    /* State #2: comma, expecting '\0' or ':' */

    switch (*val) {

    case ':':
    case '\0':
      *val_ptr = val;
      ret = DFL_ck_alloc((p + 1) * sizeof(u32));
      memcpy(ret, rec, p * sizeof(u32));
      ret[p] = END_MARKER;
      return ret;

    case ',':
      val ++;
      break;

    default:
      return NULL;

    }

  }

  FATAL("Too many ciphers or extensions in line %u.", line_no);

}


/* Is u32 list of ciphers/extensions matching the signature?
   first argument is record (star and question mark allowed),
   second one is an exact signature. */

static int match_sigs(u32* rec, u32* sig) {

  u8 match_any = 0;
  u32* tmp_sig;

  /* Iterate over record. */

  for (; *rec != END_MARKER && *sig != END_MARKER; rec++) {

    /* 1. Exact match, move on */
    if ((*rec & ~MATCH_MAYBE) == *sig) {
      match_any = 0; sig++;
      continue;
    }

    /* 2. Star, may match anything */
    if (*rec == MATCH_ANY) {
      match_any = 1;
      continue;
    }

    /* 3. Optional match, not yet fulfilled */
    if (*rec & MATCH_MAYBE) {
      if (match_any) {
        /* Look forward for the value (aka: greedy match). */
        for (tmp_sig = sig; *tmp_sig != END_MARKER; tmp_sig++) {
          if ((*rec & ~MATCH_MAYBE) == *tmp_sig) {
            /* Got it. */
            match_any = 0; sig = tmp_sig + 1;
            break;
          }
        }
      }
      /* Loop succeeded or optional match failed, whatever, go on. */
      continue;
    }

    /* 4. Looking for an exact match after MATCH_ANY */
    if (match_any) {
      for (; *sig != END_MARKER; sig++) {
        if (*rec == *sig) {
          sig ++;
          break;
        }
      }
      /* Sig is next char after match or END_MARKER */
      match_any = 0;
      continue;
    }

    /* 5. Nope, not matched. */
    return 1;

  }

  /* Right, we're after the loop, either rec or sig are set to END_MARKER */

  /* Step 1. Roll rec while it has conditional matches.
             Sig is END_MARKER if rec is not done.  */
  for (;(*rec & MATCH_MAYBE) || *rec == MATCH_ANY; rec ++) {};

  /* Step 2. Both finished - hurray. */
  if (*rec == END_MARKER && *sig == END_MARKER)
    return 0;

  /* Step 3. Rec is done and we're in MATCH_ANY mode - hurray. */
  if (*rec == END_MARKER && match_any)
    return 0;

  /* Step 4. Nope. */
  return 1;

}


static void ssl_find_match(struct ssl_sig* ts) {

  u32 i;

  for (i = 0; i < signatures_cnt; i++) {

    struct ssl_sig_record* ref = &signatures[i];
    struct ssl_sig* rs = CP(ref->sig);

    /* SSL versions must match exactly. */
    if (rs->request_version != ts->request_version) continue;

    /* Flags - exact match */
    if (ts->flags != rs->flags) continue;

    /* Extensions match. */
    if (match_sigs(rs->extensions, ts->extensions) != 0) continue;

    /* Cipher suites match. */
    if (match_sigs(rs->cipher_suites, ts->cipher_suites) != 0) continue;

    ts->matched = ref;
    return;

  }

}


/* Unpack SSLv2 header to a signature.
   -1 on parsing error, 1 if signature was extracted. */

static int fingerprint_ssl_v2(struct ssl_sig* sig, const u8* pay, u32 pay_len) {

  const u8* pay_end = pay + pay_len;
  const u8* tmp_end;

  if (pay + sizeof(struct ssl2_hdr) > pay_end) goto too_short;

  struct ssl2_hdr* hdr = (struct ssl2_hdr*)pay;
  pay += sizeof(struct ssl2_hdr);

  if (hdr->ver_min == 2 && hdr->ver_maj == 0) {

    /* SSLv2 is actually 0x0002 on the wire. */
    sig->request_version = 0x0200;

  } else {

    /* Most often - SSLv2 header has request version set to 3.x */
    sig->request_version = (hdr->ver_maj << 8) | hdr->ver_min;

  }


  u16 cipher_spec_len = ntohs(hdr->cipher_spec_length);

  if (cipher_spec_len % 3) {

    DEBUG("[#] SSLv2 cipher_spec_len=%u is not divisable by 3.\n",
          cipher_spec_len);
    return -1;

  }

  if (pay + cipher_spec_len > pay_end) goto too_short;

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

  /* Although SSLv2 states that challenge must be between 16 and 32
     bytes long, in practice no other values were recorded. 32 seems
     to be more popular than 16. */

  if (challenge_len != 32) {

    sig->flags |= SSL_FLAG_CHLEN;

    if (challenge_len != 16) {
      DEBUG("[#] SSLv2 challenge_len %i req_ver=%04x\n", challenge_len,
            sig->request_version);
    }

  }

  if (pay + session_id_len + challenge_len > pay_end) {

    DEBUG("[#] SSLv2 frame truncated (but valid) req_ver=%04x\n",
          sig->request_version);
    goto truncated;

  }

  pay += session_id_len;

  u32 i;
  u32* challenge = (u32*)pay;

  for (i = 0; i < challenge_len/4; i++) {
    if (challenge[i] == 0x00000000 || challenge[i] == 0xffffffff) {

      sig->flags |= SSL_FLAG_RAND;
      break;

    }
  }


  pay += challenge_len;

  if (pay != pay_end) {

    DEBUG("[#] SSLv2 extra %u bytes remaining after client-hello message.\n",
          pay_end - pay);

  }

truncated:

  sig->extensions = ck_alloc(1 * sizeof(u32));
  sig->extensions[0] = END_MARKER;

  return 1;


too_short:

  DEBUG("[#] SSLv2 frame too short.\n");

  ck_free(sig->cipher_suites);
  ck_free(sig->extensions);

  return -1;

}


/* Unpack SSLv3 fragment to a signature. We expect to hear ClientHello
 message.  -1 on parsing error, 1 if signature was extracted. */

static int fingerprint_ssl_v3(struct ssl_sig* sig, const u8* fragment,
                              u32 frag_len, u16 record_version) {

  int i;
  const u8* frag_end = fragment + frag_len;

  struct ssl3_message_hdr* msg = (struct ssl3_message_hdr*)fragment;
  u32 msg_len = (msg->length[0] << 16) |
                (msg->length[1] << 8) |
                (msg->length[2]);

  const u8* pay = (const u8*)msg + sizeof(struct ssl3_message_hdr);
  const u8* pay_end = pay + msg_len;
  const u8* tmp_end;


  /* Record size goes beyond current fragment, it's fine by SSL but
     not for us. */

  if (pay_end > frag_end) {
    /* I've seen a packet which looked like fragmented, but upon
       inspection I noticed that 4th byte of data had been cleared
       (high bits of frame length). Weird, ain't? */

    DEBUG("[#] SSL Fragment coalescing not supported - %u bytes requested.\n",
          pay_end - frag_end);

    return -1;

  }

  if (msg->message_type != SSL3_MSG_CLIENT_HELLO) {

    /* Rfc526 says: The handshake protocol messages are presented
         below in the order they MUST be sent; sending handshake
         messages in an unexpected order results in a fatal error.

       I guess we can assume that the first frame must be ClientHello.
    */

    DEBUG("[#] SSL Message type 0x%02x (%u bytes) is not ClientHello.\n",
          msg->message_type, msg_len);
    return -1;

  }


  /* ClientHello */


  /* Header (34B) + session_id_len (1B) */

  if (pay + 2 + 4 + 28 + 1 > pay_end) goto too_short;

  sig->request_version = (pay[0] << 8) | pay[1];
  pay += 2;

  if (sig->request_version != record_version) {
    sig->flags |= SSL_FLAG_VER;
  }

  sig->remote_time = ntohl(*((u32*)pay));
  pay += 4;

  s64 drift = ((s64)sig->recv_time) - sig->remote_time;

  if (sig->remote_time < 1*365*24*60*60) {

    /* Old Firefox on windows uses time since boot */
    sig->flags |= SSL_FLAG_STIME;

  } else if (abs(drift) > 5*365*24*60*60) {

    /* More than 5 years difference - most likely random */
    sig->flags |= SSL_FLAG_RTIME;

    DEBUG("[#] SSL timer looks random: drift=%lld remote_time=%u.\n",
          drift, sig->remote_time);

  }

  /* Random */
  u32* random = (u32*)pay;
  pay += 28;

  for (i = 0; i < 7; i++) {
    if (random[i] == 0x00000000 || random[i] == 0xffffffff) {

      sig->flags |= SSL_FLAG_RAND;
      break;

    }
  }

  /* Skip session_id */
  u8 session_id_len = pay[0];
  pay += 1;

  if (pay + session_id_len + 2 > pay_end) goto too_short;

  pay += session_id_len;


  /* Cipher suites */

  u16 cipher_suites_len = (pay[0] << 8) | pay[1];
  pay += 2;

  if (cipher_suites_len % 2) {

    DEBUG("[#] SSL cipher_suites_len=%u is not even.\n", cipher_suites_len);
    return -1;

  }

  if (pay + cipher_suites_len > pay_end) goto too_short;

  int cipher_pos = 0;
  sig->cipher_suites = ck_alloc(((cipher_suites_len / 2) + 1) * sizeof(u32));
  tmp_end = pay + cipher_suites_len;

  while (pay < tmp_end) {

    sig->cipher_suites[cipher_pos++] = (pay[0] << 8) | pay[1];
    pay += 2;

  }
  sig->cipher_suites[cipher_pos] = END_MARKER;

  if (pay + 1 > pay_end) goto truncated;

  u8 compression_methods_len = pay[0];
  pay += 1;

  if (pay + compression_methods_len > pay_end) goto truncated;

  tmp_end = pay + compression_methods_len;

  while (pay < tmp_end) {

    if (pay[0] == 1) {
      sig->flags |= SSL_FLAG_COMPR;
    } else {
      if (pay[0] || pay + 1 != tmp_end)
        DEBUG("[#] SSL unknown compression method 0x%x at offset %i/%i.\n",
              pay[0], tmp_end - pay, compression_methods_len);
    }

    pay += 1;

  }


  if (pay + 2 > pay_end) {

    /* SSL 3.0 and all versions of TLS allow the ClientHello message
       to be truncated after compression_methods and not specify
       extensions field at all. Although rarely, this does seem to
       occur in real world. Semantically it is no different to sending
       an empty list of extensions. In fact, no client was ever
       recorded to send an empty list of extensions if the extensions
       field was present. In other words - if the extensions field is
       empty you can assume the ClientHello packet was truncated after
       compression_methods. */
    goto truncated_ok;

  }

  u16 extensions_len = (pay[0] << 8) | pay[1];
  pay += 2;

  if (pay + extensions_len > pay_end) goto truncated;

  int extensions_pos = 0;
  sig->extensions = ck_alloc(((extensions_len / 4) + 1) * sizeof(u32));
  tmp_end = pay + extensions_len;

  while (pay + 4 <= tmp_end) {

    u16 ext_type = (pay[0] << 8) | pay[1];
    u16 ext_len  = (pay[2] << 8) | pay[3];
    const u8* extension = &pay[4];
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

  }

  if (pay != pay_end) {

    DEBUG("[#] SSL ClientHello remaining %i bytes after extensions.\n",
          pay_end - pay);

  }

  if (pay_end != frag_end) {

    DEBUG("[#] SSL %i bytes remaining after ClientHello message.\n",
          frag_end - pay_end);

  }

  if (0) {
truncated:

    DEBUG("[#] SSL packet truncated (but valid) req_ver=%04x rec_ver=%04x\n",
          sig->request_version, record_version);

  }
truncated_ok:

  if (!sig->extensions) {
    sig->extensions    = ck_alloc(1*sizeof(u32));
    sig->extensions[0] = END_MARKER;
  }

  return 1;


too_short:

  DEBUG("[#] SSL packet truncated.\n");

  ck_free(sig->cipher_suites);
  ck_free(sig->extensions);

  return -1;

}


/* Signature - to - string */

static u8* dump_sig(struct ssl_sig* sig, u8 fingerprint) {

  int i;

  static u8* ret;
  u32 rlen = 0;

#define RETF(_par...) do {                           \
    s32 _len = snprintf(NULL, 0, _par);              \
    if (_len < 0) FATAL("Whoa, snprintf() fails?!"); \
    ret = DFL_ck_realloc_kb(ret, rlen + _len + 1);   \
    snprintf((char*)ret + rlen, _len + 1, _par);     \
    rlen += _len;                                    \
  } while (0)

  RETF("%i.%i:", sig->request_version >> 8, sig->request_version & 0xFF);

  for (i = 0; sig->cipher_suites[i] != END_MARKER; i++) {
    u32 c = sig->cipher_suites[i];
    if (c != MATCH_ANY) {
      RETF("%s%s%x", (i ? "," : ""),
           (c & MATCH_MAYBE) ? "?" : "",
           c & ~MATCH_MAYBE);
    } else {
      RETF("%s*", (i ? "," : ""));
    }
  }

  RETF(":");

  for (i = 0; sig->extensions[i] != END_MARKER; i++) {
    u32 ext = sig->extensions[i];
    if (ext != MATCH_ANY) {
      u8 optional = 0;
      if (fingerprint && ext == 0) {
        optional = 1;
      }
      RETF("%s%s%x", (i ? "," : ""),
           ((ext & MATCH_MAYBE) || optional) ? "?" : "",
           ext & ~MATCH_MAYBE);
    } else {
      RETF("%s*", (i ? "," : ""));
    }
  }

  RETF(":");

  int had_prev = 0;
  for (i = 0; flags[i].name != NULL; i++) {

    if (sig->flags & flags[i].value) {
      RETF("%s%s", (had_prev ? "," : ""), flags[i].name);
      had_prev = 1;
    }

  }

  return ret;

}


/* Register new SSL signature. */

void ssl_register_sig(u8 to_srv, u8 generic, s32 sig_class, u32 sig_name,
                      u8* sig_flavor, u32 label_id, u32* sys, u32 sys_cnt,
                      u8* val, u32 line_no) {

  struct ssl_sig* ssig;
  struct ssl_sig_record* srec;

  /* Client signatures only. */
  if (to_srv != 1) return;

  /* Only "application" signatures supported, no "OS-identifying". */
  if (sig_class != -1)
    FATAL("OS-identifying SSL signatures not supported, use \"!\" instead "
          "of an OS class in line %u.", line_no);

  ssig = DFL_ck_alloc(sizeof(struct ssl_sig));

  signatures = DFL_ck_realloc(signatures, (signatures_cnt + 1) *
                              sizeof(struct ssl_sig_record));

  srec = &signatures[signatures_cnt];


  int maj = strtol((char*)val, (char**)&val, 10);
  if (!val || *val != '.') FATAL("Malformed signature in line %u.", line_no);
  val ++;
  int min = strtol((char*)val, (char**)&val, 10);
  if (!val || *val != ':') FATAL("Malformed signature in line %u.", line_no);
  val ++;

  ssig->request_version = (maj << 8) | min;

  ssig->cipher_suites = decode_hex_string((const u8**)&val, line_no);
  if (!val || *val != ':' || !ssig->cipher_suites)
    FATAL("Malformed signature in line %u.", line_no);
  val ++;

  ssig->extensions = decode_hex_string((const u8**)&val, line_no);
  if (!val || *val != ':' || !ssig->extensions)
    FATAL("Malformed signature in line %u.", line_no);
  val ++;


  while (*val) {

    int i;
    for (i = 0;  flags[i].name != NULL; i++) {

      if (!strncmp((char*)val, flags[i].name, flags[i].name_len)) {
        ssig->flags |= flags[i].value;
        val += flags[i].name_len;
        goto flag_matched;
      }

    }

    FATAL("Unrecognized flag in line %u.", line_no);

  flag_matched:

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

  signatures_cnt++;

}

static void score_nat(u8 to_srv, struct packet_flow* f, struct ssl_sig* sig) {

  struct ssl_sig_record* m = sig->matched;
  struct host_data* hd;

  u8  score = 0;
  u16 reason = 0;

  /* Client request only. */
  if (to_srv != 1) return;

  hd = f->client;


  if (m && m->class_id == -1) {

    /* Application signature: we might look at the OS-es mentioned by
       the signature, and make sure the OS from http and/or TCP
       matches. */

    verify_tool_class(to_srv, f, m->sys, m->sys_cnt);

  }

  if (hd->ssl_remote_time && sig->remote_time &&
      (sig->flags & SSL_FLAG_RTIME) == 0) {

    /* Time on the client should be increasing monotically */

    s64 recv_diff    = ((s64)sig->recv_time) - hd->ssl_recv_time;
    s64 remote_diff  = ((s64)sig->remote_time) - hd->ssl_remote_time;

    if (remote_diff < recv_diff - SSL_MAX_TIME_DIFF ||
        remote_diff > recv_diff + SSL_MAX_TIME_DIFF) {

      DEBUG("[#] SSL gmt_unix_time skew too high (%lld in %lld sec).\n",
            remote_diff, recv_diff);

      score += 4;
      reason |= NAT_APP_DATE;

    }

  }

  add_nat_score(to_srv, f, reason, score);

}



/* Given an SSL client signature look it up and create an observation.  */

static void fingerprint_ssl(u8 to_srv, struct packet_flow* f,
                            struct ssl_sig* sig) {

  /* Client request only. */
  if (to_srv != 1) return;

  ssl_find_match(sig);

  struct ssl_sig_record* m = sig->matched;

  start_observation("ssl request", 5, to_srv, f);

  if (m) {

    /* Found matching signature */

    OBSERVF((m->class_id < 0) ? "app" : "os", "%s%s%s",
            fp_os_names[m->name_id], m->flavor ? " " : "",
            m->flavor ? m->flavor : (u8*)"");

    add_observation_field("match_sig", dump_sig(sig->matched->sig, 0));

  } else {

    add_observation_field("app", NULL);
    add_observation_field("match_sig", NULL);

  }

  if ((sig->flags & (SSL_FLAG_RTIME | SSL_FLAG_STIME)) == 0) {

    s64 drift = ((s64)sig->recv_time) - sig->remote_time;
    OBSERVF("drift", "%lld", drift);

  } else {

    add_observation_field("drift", NULL);

  }

  OBSERVF("remote_time", "%u", sig->remote_time);

  add_observation_field("raw_sig", dump_sig(sig, 1));

  score_nat(to_srv, f, sig);

}


/* Examine request or response; returns 1 if more data needed and
   plausibly can be read. Note that the buffer is always NULL
   terminated. */

u8 process_ssl(u8 to_srv, struct packet_flow* f) {

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

  struct ssl2_hdr* hdr2 = (struct ssl2_hdr*)f->request;
  u16 msg_length = ntohs(hdr2->msg_length);

  struct ssl3_record_hdr* hdr3 = (struct ssl3_record_hdr*)f->request;
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
    sig.recv_time = f->client->last_seen;
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
    sig.recv_time = f->client->last_seen;
    u16 record_version = (hdr3->ver_maj << 8) | hdr3->ver_min;

    u8* fragment = f->request + sizeof(struct ssl3_record_hdr);

    success = fingerprint_ssl_v3(&sig, fragment, fragment_len, record_version);

  }

  if (success != 1) {

    DEBUG("[#] Does not look like SSLv2 nor SSLv3.\n");

    f->in_ssl = -1;
    return 0;

  }


  f->in_ssl = 1;

  fingerprint_ssl(to_srv, f, &sig);

  if (sig.remote_time && !(sig.flags & SSL_FLAG_RTIME)) {
    f->client->ssl_remote_time = sig.remote_time;
    f->client->ssl_recv_time   = sig.recv_time;
  }


  ck_free(sig.cipher_suites);
  ck_free(sig.extensions);

  return 0;

}
