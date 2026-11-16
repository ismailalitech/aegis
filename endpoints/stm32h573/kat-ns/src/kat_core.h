/* SPDX-License-Identifier: Apache-2.0 */
#ifndef KAT_CORE_H
#define KAT_CORE_H
typedef void (*kat_out_fn)(const char *s);
void kat_handle(const char *line, kat_out_fn out);
#endif
