#include "peregrine_socket.h"

/*
 * uses bitmap for remembering which nodes have already been sent in INTEGRITY
 *
 */
int
make_integrity_reverse(char *ptr, struct peregrine_peer *peer)
{
  //   char *d;
  //   int ret;
  //   int ic;
  //   int f;
  //   struct node *n;
  //   struct node *s;
  //   struct node l;
  //   struct node r;
  //   struct node *e;
  //   struct node *n_subroot;
  //   struct integrity_temp *it;
  //   struct integrity_temp *it2;
  //   int16_t iti;
  //   int16_t itn;
  //   int16_t iti2;
  //   int16_t itn2;
  //   uint32_t b;
  //   uint32_t i;
  //   uint32_t v;
  //   uint32_t nc;
  //   uint32_t v_start;
  //   uint32_t v_end;

  //   d = ptr;

  //   *(uint32_t *)d = htobe32(peer->dest_chan_id);
  //   d += sizeof(uint32_t);

  //   _assert(peer->file_list_entry != NULL, "%s", "peer->file_list_entry should be != NULL\n");
  //   _assert(peer->integrity_bmp != NULL, "%s", "peer->integrity_bmp should be != NULL\n");

  //   it = malloc(1024 * sizeof(struct integrity_temp));
  //   _assert(it != NULL, "%s", "it should be != NULL\n");
  //   itn = 0;

  //   it2 = malloc(1024 * sizeof(struct integrity_temp));
  //   _assert(it2 != NULL, "%s", "it2 should be != NULL\n");
  //   itn2 = 0;

  //   _assert(peer->curr_chunk <= peer->file_list_entry->nc, "curr_chunk must be <= nc, but curr_chunk: %lu and nc:
  //   %u\n",
  //           peer->curr_chunk, peer->file_list_entry->nc);

  //   /* to be compatible with libswift determine subranges
  //    * example for num_chunks == 7:
  //    * 0..3=4, 4..5=2, 6..6=1
  //    * 7=(111)2 - for every bit set (b2, b1, b0) determine subrange equal to
  //    * weight of given bit for b2 set it will be subrange: 0..3 - because b2 has
  //    * weight 4 for b1 set it will be next subrange 4..5 - because b1 has weight 2
  //    * for b0 set it will be next subrange 6..6 - because b0 has weight 1
  //    */
  //   nc = peer->file_list_entry->end_chunk - peer->file_list_entry->start_chunk + 1;
  //   b = 31;
  //   i = 0;
  //   v = 0;
  //   while (i < 32) {
  //     if (nc & (1 << b)) {
  //       d_printf("INTEGRITY: %u..%u\n", v, v + (1 << b) - 1);

  //       v_start = v;
  //       v_end = v + (1 << b) - 1;
  //       it[itn].start_chunk = v_start; /* start of subrange */
  //       it[itn].end_chunk = v_end;     /* end of subrange */

  //       v_root = v_start + v_end;
  //       e = &peer->file_list_entry->tree[v_root]; /* "e" is subroot of subtree v..v+(1<<b)-1 */

  //       if (!(peer->integrity_bmp[v_root / 8] & (1 << (v_root % 8)))) {
  // 	memcpy(it[itn].sha, e->sha, 20);
  // 	d_printf("it[%d] %u..%u\n", itn, it[itn].start_chunk, it[itn].end_chunk);
  // 	itn++;
  // 	/* update INTEGRITY bitmap */
  // 	peer->integrity_bmp[v_root / 8] |= (1 << (v_root % 8));
  //       }
  //       v = v + (1 << b);
  //     }
  //     i++;
  //     b--;
  //   }
}
