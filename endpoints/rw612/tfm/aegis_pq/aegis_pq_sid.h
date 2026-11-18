#ifndef AEGIS_PQ_SID_H
#define AEGIS_PQ_SID_H
/* Shared by the secure partition and the non-secure client.
 * Handle = (1 << 30) | (version << 8) | stateless index.  Index 0x10 = manifest "stateless_handle": 17.
 * Indices 0x0..0xB are taken by SDK partitions (crypto 0, PS 1, ITS 2, attest 3, FWU 4, platform 5,
 * IPC test 6/7, SLIH 8, FLIH 9, SFN test 10, loader service 11). Must equal the low bits of
 * SERVICE_FLAG_STATELESS | 0x10 in load_info_aegis_pq.c. */
#define AEGIS_PQ_SERVICE_SID            (0x0000AE10U)
#define AEGIS_PQ_SERVICE_VERSION        (1U)
#define AEGIS_PQ_SERVICE_HANDLE         (0x40000110U)
#endif
