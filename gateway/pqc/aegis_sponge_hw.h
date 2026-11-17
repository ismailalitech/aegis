/* SPDX-License-Identifier: Apache-2.0
 * aegis_pqc2 sponge registers (hw/rtl/aegis_pqc2.v) and the access interface shared by the board path (UIO MMIO) and
 * the PC model (aegis_sponge_model.c). */
#ifndef AEGIS_SPONGE_HW_H
#define AEGIS_SPONGE_HW_H
#include <stddef.h>
#include <stdint.h>

#define SP_ID      0x00u
#define SP_CTRL    0x04u
#define SP_STATUS  0x08u
#define SP_KCOUNT  0x0Cu
#define SP_SCMD    0x1Cu
#define SP_SCFG    0x20u
#define SP_DMALO   0x24u
#define SP_DMAHI   0x28u
#define SP_LANE    0x38u          /* word w at 0x38 + 4w: lane w/2, half w%2 */
#define SP_ID_V2   0xAE150002u

#define SP_CMD_PERMUTE 1u
#define SP_CMD_CLEAR   2u
#define SP_CMD_SELECT  3u
#define SP_CMD_SQUEEZE 4u
#define SP_ST_DMA_BUSY (1u << 16)
#define SP_ST_DMA_ERR  (1u << 17)
#define SP_SLOTS 8

struct aegis_sponge_io {
	uint32_t (*rd)(void *priv, uint32_t off);
	void (*wr)(void *priv, uint32_t off, uint32_t v);
	void *priv;
	/* DMA buffer: dma_va maps the physical range [dma_pa, dma_pa + dma_len) without caching; dma_len 0 = no DMA */
	volatile uint8_t *dma_va;
	uint64_t dma_pa;
	size_t dma_len;
};

/* PC model of the register interface. mem_write: DMA beat to physical address pa, return nonzero for an error response */
struct aegis_sponge_model;
struct aegis_sponge_model *aegis_sponge_model_new(int (*mem_write)(void *ctx, uint64_t pa, uint64_t v), void *ctx);
uint32_t aegis_sponge_model_rd(void *m, uint32_t off);
void aegis_sponge_model_wr(void *m, uint32_t off, uint32_t v);
void aegis_sponge_model_free(struct aegis_sponge_model *m);
/* replace the model's own permutation (standard lane order, no complementing), e.g. by a faster one */
void aegis_sponge_model_set_permute(struct aegis_sponge_model *m, void (*f)(uint64_t a[25]));
#endif
