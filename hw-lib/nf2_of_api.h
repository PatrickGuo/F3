#include <stdint.h>
#include "../oflib/ofl.h"
#include "../oflib/ofl-actions.h"
#include "../oflib/ofl-messages.h"
#include "../oflib/ofl-structs.h"

#define NF2_OF_ENTRY_WORD_LEN	   8
#define NF2_OF_MASK_WORD_LEN	   8
#define NF2_OF_ACTION_WORD_LEN	10

#define DEFAULT_IFACE	"onet"

#pragma pack(1)
struct nf2_of_entry {
	uint16_t transp_dst;
	uint16_t transp_src;
	uint8_t ip_proto;
	uint32_t ip_dst;
	uint32_t ip_src;
	uint16_t eth_type;
	uint8_t eth_dst[6];
	uint8_t eth_src[6];
	uint8_t src_port;
	uint8_t ip_tos;
	uint16_t vlan_id;
	uint8_t pad;
};

typedef union nf2_of_entry_wrap {
	struct nf2_of_entry entry;
	uint32_t raw[NF2_OF_ENTRY_WORD_LEN];
} nf2_of_entry_wrap;

typedef nf2_of_entry_wrap nf2_of_mask_wrap;

struct nf2_of_action {
	uint16_t forward_bitmask; // output to which port (only four ports: 0_0_0_0_)
	uint16_t nf2_action_flag; // different bits respond to different action
	// The following variables are used for SET_FIELD command
  uint16_t vlan_id;
	uint8_t vlan_pcp;
	uint8_t eth_src[6];
	uint8_t eth_dst[6];
	uint32_t ip_src;
	uint32_t ip_dst;
	uint8_t ip_tos;
	uint16_t transp_src;
	uint16_t transp_dst;
	uint8_t reserved[8];
};

typedef union nf2_of_action_wrap {
	struct nf2_of_action action;
	uint32_t raw[NF2_OF_ACTION_WORD_LEN];
} nf2_of_action_wrap;
#pragma pack()

void nf2_flow_entry_init(nf2_of_entry_wrap*, nf2_of_mask_wrap*, nf2_of_action_wrap*);
int nf2_install_flow_entry(struct nf2device *dev, int row, nf2_of_entry_wrap *entry, nf2_of_mask_wrap *mask, nf2_of_action_wrap *action);
int nf2_clear_flow_entry(struct nf2device* dev, int row);
void nf2_flow_read(struct nf2device* dev, int row);
int nf2_set_meter(struct nf2device *dev, int meter_id, int kbps);
int nf2_clear_meter(struct nf2device* dev, int meter_id);
void nf2_read_meter(struct nf2device* dev, int meter_id);

size_t hw_table_flow_mod(struct ofl_msg_flow_mod *msg);

size_t ofl_msg_2_nf2(struct ofl_msg_flow_mod *msg, nf2_of_entry_wrap *nf2_entry_p, 
   nf2_of_mask_wrap *nf2_mask_p, nf2_of_action_wrap *nf2_action_p);

size_t ofl_match_2_nf2(struct ofl_match_header *match_header, nf2_of_entry_wrap *nf2_entry_p,
   nf2_of_mask_wrap *nf2_mask_p);

void parse_oxm_tlv(  struct ofl_match_tlv *f, nf2_of_entry_wrap *nf2_entry_p, nf2_of_mask_wrap *nf2_mask_p);

void ofl_instruction_2_nf2(struct ofl_instruction_header *inst, nf2_of_action_wrap *nf2_action_p);

void set_forward_bitmask(nf2_of_action_wrap *nf2_action_p, uint32_t port);

void ofl_action_2_nf2(struct ofl_action_header *act, nf2_of_action_wrap *nf2_action_p);

void parse_oxm_tlv_action(  struct ofl_match_tlv *f, nf2_of_action_wrap *nf2_action_p);


