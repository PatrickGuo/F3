#include<stdio.h>  
#include<unistd.h>  
#include<sys/mman.h>
#include<sys/types.h>  
#include<sys/stat.h>  
#include<fcntl.h>
#include<stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include<netinet/in.h>

#include "nf2.h"
#include "nf2util.h"

#include "reg_defines_openflow_switch.h"

#include "../oflib/ofl.h"
#include "../oflib/ofl-actions.h"
#include "../oflib/ofl-messages.h"
#include "../oflib/ofl-structs.h"
#include "../oflib/oxm-match.h"
#include "nf2_of_api.h"


void nf2_flow_entry_init(nf2_of_entry_wrap* entry, nf2_of_mask_wrap* mask, nf2_of_action_wrap* action){
   memset(entry, 0, NF2_OF_ENTRY_WORD_LEN*4);
   memset(mask, 0xff, NF2_OF_ENTRY_WORD_LEN*4);
   memset(action, 0, NF2_OF_ACTION_WORD_LEN*4);
}

int nf2_install_flow_entry(struct nf2device *dev, int row,
		      nf2_of_entry_wrap *entry, nf2_of_mask_wrap *mask,
		      nf2_of_action_wrap *action)
{
	int i;
	unsigned int val;

	for (i = 0; i < NF2_OF_ENTRY_WORD_LEN; ++i) {
		writeReg(dev, OPENFLOW_WILDCARD_LOOKUP_CMP_0_REG + (4 * i), entry->raw[i]);
	}

	for (i = 0; i < NF2_OF_MASK_WORD_LEN; ++i) {
		writeReg(dev, OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_0_REG + (4 * i), mask->raw[i]);
	}

	for (i = 0; i < NF2_OF_ACTION_WORD_LEN; ++i) {
		writeReg(dev, OPENFLOW_WILDCARD_LOOKUP_ACTION_0_REG + (4 * i), action->raw[i]);
	}
	// Reset the stats for the row
	val = 0;
	writeReg(dev, OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_0_REG + (4 * row), val);
	writeReg(dev, OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_0_REG + (4 * row), val);
	writeReg(dev, OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_0_REG + (4 * row), val);
	writeReg(dev, OPENFLOW_WILDCARD_LOOKUP_WRITE_ADDR_REG, row);
	return 0;
}

void nf2_flow_read(struct nf2device* dev, int row){
   unsigned val;
   int i;
   nf2_of_entry_wrap entry;
   nf2_of_mask_wrap mask;
   nf2_of_action_wrap action;

   writeReg(dev, OPENFLOW_WILDCARD_LOOKUP_READ_ADDR_REG, row);
   for (i = 0; i < NF2_OF_ENTRY_WORD_LEN; ++i) {
      readReg(dev, OPENFLOW_WILDCARD_LOOKUP_CMP_0_REG + (4 * i), &val);
      printf("cmp_data reg %d: %x\n", i,val);
      entry.raw[i] = val;
	}
   printf("\n");
	for (i = 0; i < NF2_OF_ENTRY_WORD_LEN; ++i) {
		readReg(dev, OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_0_REG + (4 * i), &val);
      printf("cmp_mask reg %d: %x\n", i,val);
      mask.raw[i] = val;
	}
   printf("\n");
	for (i = 0; i < NF2_OF_ACTION_WORD_LEN; ++i) {
		readReg(dev,OPENFLOW_WILDCARD_LOOKUP_ACTION_0_REG + (4 * i), &val);
      printf("action reg %d: %x\n", i,val);
      action.raw[i] = val;
	}
   printf("\n");
   val = 0;
	readReg(dev, OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_0_REG + (4 * row), &val);
   printf("bytes counter: %x\n", val);
	readReg(dev, OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_0_REG + (4 * row), &val);
   printf("pkts counter: %x\n", val);
	readReg(dev, OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_0_REG + (4 * row), &val);
   printf("last seen time: %x\n", val);
   printf("\n");
   printf("======================flow entry explaination===================\n");
   printf("transp_dst: %d\n", entry.entry.transp_dst);
   printf("transp_src: %d\n", entry.entry.transp_src);
   printf("ip_proto: %d\n", entry.entry.ip_proto);
   printf("ip_dst: %d.%d.%d.%d\n", entry.entry.ip_dst >> 24 & 0x000000ff, entry.entry.ip_dst >> 16 & 0x000000ff, entry.entry.ip_dst >> 8 & 0x000000ff, entry.entry.ip_dst & 0x000000ff);
   printf("ip_src: %d.%d.%d.%d\n", entry.entry.ip_src >> 24 & 0x000000ff, entry.entry.ip_src >> 16 & 0x000000ff, entry.entry.ip_src >> 8 & 0x000000ff, entry.entry.ip_src & 0x000000ff);
   printf("eth_type: %02x\n", entry.entry.eth_type);
   printf("eth_dst: %02x:%02x:%02x:%02x:%02x:%02x\n", entry.entry.eth_dst[0], entry.entry.eth_dst[1], entry.entry.eth_dst[2], entry.entry.eth_dst[3], entry.entry.eth_dst[4], entry.entry.eth_dst[5]);
   printf("eth_src: %02x:%02x:%02x:%02x:%02x:%02x\n", entry.entry.eth_src[0], entry.entry.eth_src[1], entry.entry.eth_src[2], entry.entry.eth_src[3], entry.entry.eth_src[4], entry.entry.eth_src[5]);
   printf("src_port: %d\n", entry.entry.src_port);
   printf("ip_tos: %d\n", entry.entry.ip_tos);
   printf("vlan_id: %d\n", entry.entry.vlan_id);

   printf("mask transp_dst: %02x\n", mask.entry.transp_dst);
   printf("mask transp_src: %02x\n", mask.entry.transp_src);
   printf("mask ip_proto: %02x\n", mask.entry.ip_proto);
   printf("mask ip_dst: %d.%d.%d.%d\n", mask.entry.ip_dst >> 24 & 0x000000ff, mask.entry.ip_dst >> 16 & 0x000000ff, mask.entry.ip_dst >> 8 & 0x000000ff, mask.entry.ip_dst & 0x000000ff);
   printf("mask ip_src: %d.%d.%d.%d\n", mask.entry.ip_src >> 24 & 0x000000ff, mask.entry.ip_src >> 16 & 0x000000ff, mask.entry.ip_src >> 8 & 0x000000ff, mask.entry.ip_src & 0x000000ff);
   printf("mask eth_type: %02x\n", mask.entry.eth_type);
   printf("mask eth_dst: %02x:%02x:%02x:%02x:%02x:%02x\n", mask.entry.eth_dst[0], mask.entry.eth_dst[1], mask.entry.eth_dst[2], mask.entry.eth_dst[3], mask.entry.eth_dst[4], mask.entry.eth_dst[5]);
   printf("mask eth_src: %02x:%02x:%02x:%02x:%02x:%02x\n", mask.entry.eth_src[0], mask.entry.eth_src[1], mask.entry.eth_src[2], mask.entry.eth_src[3], mask.entry.eth_src[4], mask.entry.eth_src[5]);
   printf("mask src_port: %02x\n", mask.entry.src_port);
   printf("mask ip_tos: %02x\n", mask.entry.ip_tos);
   printf("mask vlan_id: %02x\n", mask.entry.vlan_id);


   
   printf("actions contained: \n");
   printf("nf2_action_flag: %04x\n", action.action.nf2_action_flag);
   printf("NF2_OFPAT_OUTPUT : %d\n", (action.action.nf2_action_flag & NF2_OFPAT_OUTPUT) == 0 ? 0 : 1);
   printf("NF2_OFPAT_SET_VLAN_VID : %d\n", (action.action.nf2_action_flag & NF2_OFPAT_SET_VLAN_VID) == 0 ? 0 : 1);
   printf("NF2_OFPAT_SET_VLAN_PCP : %d\n", (action.action.nf2_action_flag & NF2_OFPAT_SET_VLAN_PCP) == 0 ? 0 : 1);
   printf("NF2_OFPAT_STRIP_VLAN : %d\n", (action.action.nf2_action_flag & NF2_OFPAT_STRIP_VLAN) == 0 ? 0 : 1);
   printf("NF2_OFPAT_SET_DL_SRC : %d\n", (action.action.nf2_action_flag & NF2_OFPAT_SET_DL_SRC) == 0 ? 0 : 1);
   printf("NF2_OFPAT_SET_DL_DST : %d\n", (action.action.nf2_action_flag & NF2_OFPAT_SET_DL_DST) == 0 ? 0 : 1);
   printf("NF2_OFPAT_SET_NW_SRC : %d\n", (action.action.nf2_action_flag & NF2_OFPAT_SET_NW_SRC) == 0 ? 0 : 1);
   printf("NF2_OFPAT_SET_NW_DST : %d\n", (action.action.nf2_action_flag & NF2_OFPAT_SET_NW_DST) == 0 ? 0 : 1);
   printf("NF2_OFPAT_SET_NW_TOS : %d\n", (action.action.nf2_action_flag & NF2_OFPAT_SET_NW_TOS) == 0 ? 0 : 1);
   printf("NF2_OFPAT_SET_TP_SRC : %d\n", (action.action.nf2_action_flag & NF2_OFPAT_SET_TP_SRC) == 0 ? 0 : 1);
   printf("NF2_OFPAT_SET_TP_DST : %d\n", (action.action.nf2_action_flag & NF2_OFPAT_SET_TP_DST) == 0 ? 0 : 1);
   printf("forward_bitmask: %04x\n", action.action.forward_bitmask);
   printf("vlan_id: %04x\n", action.action.vlan_id);
   printf("vlan_pcp: %02x\n", action.action.vlan_pcp);
   printf("eth_src: %02x:%02x:%02x:%02x:%02x:%02x\n", action.action.eth_src[0], action.action.eth_src[1], action.action.eth_src[2], action.action.eth_src[3], action.action.eth_src[4], action.action.eth_src[5]);
   printf("eth_dst: %02x:%02x:%02x:%02x:%02x:%02x\n", action.action.eth_dst[0], action.action.eth_dst[1], action.action.eth_dst[2], action.action.eth_dst[3], action.action.eth_dst[4], action.action.eth_dst[5]);
   printf("ip_src: %d.%d.%d.%d\n", action.action.ip_src >> 24 & 0x000000ff, action.action.ip_src >> 16 & 0x000000ff, action.action.ip_src >> 8 & 0x000000ff, action.action.ip_src & 0x000000ff);
   printf("ip_dst: %d.%d.%d.%d\n", action.action.ip_dst >> 24 & 0x000000ff, action.action.ip_dst >> 16 & 0x000000ff, action.action.ip_dst >> 8 & 0x000000ff, action.action.ip_dst & 0x000000ff);
   printf("ip_tos: %02x\n", action.action.ip_tos);
   printf("transp_src: %04x\n", action.action.transp_src);
   printf("transp_dst: %04x\n", action.action.transp_dst);
}

int nf2_clear_flow_entry(struct nf2device* dev, int row){
   nf2_of_entry_wrap flow_entry;
   nf2_of_mask_wrap flow_mask;
   nf2_of_action_wrap flow_action;
   
   memset(&flow_entry, 0, NF2_OF_ENTRY_WORD_LEN*4);
   memset(&flow_mask, 0, NF2_OF_ENTRY_WORD_LEN*4);
   memset(&flow_action, 0, NF2_OF_ACTION_WORD_LEN*4);
   nf2_install_flow_entry(dev,row,&flow_entry,&flow_mask,&flow_action);
   return 0;
}

unsigned int meter_addr_lookup(int meter_id){
   unsigned int meter_addr;
   switch(meter_id){
      case 0: 
         meter_addr = RATE_LIMIT_0_CTRL_REG;
         break;
      case 1: 
         meter_addr = RATE_LIMIT_1_CTRL_REG;
         break;
      case 2: 
         meter_addr = RATE_LIMIT_2_CTRL_REG;
         break;
      case 3: 
         meter_addr = RATE_LIMIT_3_CTRL_REG;
         break; 
      default: meter_addr = RATE_LIMIT_1_CTRL_REG;
   }
   return meter_addr;
}
int nf2_set_meter(struct nf2device *dev, int meter_id, int kbps){
   unsigned int inc, interval;
   unsigned int meter_addr_base;
   unsigned int a, b, temp;
   a = kbps;
   b = 8000*75;
   if(a < b){
      temp = a;
      a = b;
      b = temp;
   }
   while(b!=0){
      temp = a % b;
      a = b;
      b = temp;
   }
   inc = (unsigned int)(kbps / a);
   interval = (unsigned int)(8000 * 75 / a);
   meter_addr_base = meter_addr_lookup(meter_id);

   writeReg(dev, meter_addr_base + 4, interval);
   writeReg(dev, meter_addr_base + 8, inc);
   writeReg(dev, meter_addr_base, 1); //enable
   return 0;
}
int nf2_clear_meter(struct nf2device* dev, int meter_id){
   unsigned int meter_addr_base;
   
   meter_addr_base = meter_addr_lookup(meter_id);
   writeReg(dev, meter_addr_base + 4, 1);
   writeReg(dev, meter_addr_base + 8, 1);
   writeReg(dev, meter_addr_base, 0); //disable
}
void nf2_read_meter(struct nf2device* dev, int meter_id){
   unsigned int meter_addr_base;
   unsigned val = 0;
   unsigned inc, interval;
   unsigned int kbps;
   
   meter_addr_base = meter_addr_lookup(meter_id);
   printf("Reading meter %d...\n", meter_id);
   readReg(dev, meter_addr_base, &val); 
   printf("CTRL_REG: %x\n", val);
   readReg(dev, meter_addr_base + 4, &interval);
   printf("TOKEN_INTERVAL_REG: %x\n", interval);
   readReg(dev, meter_addr_base + 8, &inc);
   printf("TOKEN_INC_REG: %x\n", inc);
   kbps = (unsigned int) (inc * 8000 * 75) / interval;
   printf("rate: %d\n", kbps);
}

size_t hw_table_flow_mod(struct ofl_msg_flow_mod *msg){
   struct nf2device nf2;
   nf2.device_name = DEFAULT_IFACE;
   
   if (check_iface(&nf2)) return -1;
   if (openDescriptor(&nf2)) return -1;
   
   if(msg->command == OFPFC_ADD) {
      nf2_of_entry_wrap flow_entry;
      nf2_of_mask_wrap flow_mask;
      nf2_of_action_wrap flow_action;
      nf2_flow_entry_init(&flow_entry, &flow_mask, &flow_action);
      ofl_msg_2_nf2(msg, &flow_entry, &flow_mask, &flow_action);
      nf2_install_flow_entry(&nf2,msg->priority,&flow_entry,&flow_mask,&flow_action);
      
   }
   else if(msg->command == OFPFC_DELETE){
      nf2_clear_flow_entry(&nf2, msg->priority);
   }
   
   return 0;
}

/*derived from ofl_msg_print_flow_mod*/

size_t
ofl_msg_2_nf2(struct ofl_msg_flow_mod *msg, nf2_of_entry_wrap *nf2_entry_p, nf2_of_mask_wrap *nf2_mask_p, nf2_of_action_wrap *nf2_action_p) {
   size_t i;
   
   ofl_match_2_nf2(msg->match, nf2_entry_p, nf2_mask_p);
   
   for(i=0; i<msg->instructions_num; i++) 
      ofl_instruction_2_nf2(msg->instructions[i], nf2_action_p);
   
   return 0;
}

size_t
ofl_match_2_nf2(struct ofl_match_header *match_header, nf2_of_entry_wrap *nf2_entry_p, nf2_of_mask_wrap *nf2_mask_p){
   struct ofl_match_tlv *f;
   struct ofl_match *match;
   
   if(match_header->type != OFPMT_OXM) return -1;
   match = (struct ofl_match *)match_header;
   if (match->header.length) {
      HMAP_FOR_EACH(f, struct ofl_match_tlv, hmap_node, &match->match_fields){                             
         parse_oxm_tlv(f, nf2_entry_p, nf2_mask_p);
      }
   }
   return 0;
}

void 
parse_oxm_tlv(  struct ofl_match_tlv *f, nf2_of_entry_wrap *nf2_entry_p, nf2_of_mask_wrap *nf2_mask_p){

   size_t i;

   uint8_t field = OXM_FIELD(f->header);

   if (field == OFPXMT_OFB_IN_PORT){
      nf2_entry_p->entry.src_port = (*((uint8_t*) f->value)-1)*2; //TODO: ADD PORT_CALC
      nf2_mask_p->entry.src_port = 0;
   }
   else if (field == OFPXMT_OFB_IN_PHY_PORT){
      nf2_entry_p->entry.src_port = *((uint8_t*) f->value); //TODO: IF PROPER
      nf2_mask_p->entry.src_port = 0;
   }
   else if (field == OFPXMT_OFB_VLAN_VID){
      uint16_t *v = (uint16_t *) f->value;
      if (*v == OFPVID_NONE){}
         //printf( "vlan_vid= none");
      else if (*v == OFPVID_PRESENT && OXM_HASMASK(f->header)){}
         //printf( "vlan_vid= any");
      else {
         nf2_entry_p->entry.vlan_id = (*v & VLAN_VID_MASK);     
         nf2_mask_p->entry.vlan_id = 0;
      }
   }
   else if (field == OFPXMT_OFB_VLAN_PCP){
      //printf( "vlan_pcp=\"%d\"", *f->value & 0x7);                               
   } 
   else if (field == OFPXMT_OFB_ETH_TYPE){
      nf2_entry_p->entry.eth_type = *((uint16_t *) f->value);                        
      nf2_mask_p->entry.eth_type = 0;
   }
   else if (field == OFPXMT_OFB_TCP_SRC || field == OFPXMT_OFB_UDP_SRC || field == OFPXMT_OFB_SCTP_SRC){
      nf2_entry_p->entry.transp_src = *((uint16_t*) f->value);
      nf2_mask_p->entry.transp_src = 0;
   }
   else if (field == OFPXMT_OFB_TCP_DST || field == OFPXMT_OFB_UDP_DST || field == OFPXMT_OFB_SCTP_DST){
      nf2_entry_p->entry.transp_dst = *((uint16_t*) f->value);
      nf2_mask_p->entry.transp_dst = 0;   
   }
   else if (field == OFPXMT_OFB_ETH_SRC){
      for(i=0; i<6; i++){
         nf2_entry_p->entry.eth_src[5-i] = *((uint8_t*)(f->value + i));
      }                            
      if (OXM_HASMASK(f->header)){
         for(i=0; i<6; i++){
         nf2_mask_p->entry.eth_src[5-i] = *((uint8_t*)(f->value + 6 + i));
         }
      }
      else {
         for(i=0; i<6; i++){
            nf2_mask_p->entry.eth_src[i] = 0;
         }
      }
   }
   else if (field == OFPXMT_OFB_ETH_DST){
      for(i=0; i<6; i++){
         nf2_entry_p->entry.eth_dst[5-i] = *((uint8_t*)(f->value + i));
      }
      if (OXM_HASMASK(f->header)){
         for(i=0; i<6; i++){
            nf2_mask_p->entry.eth_dst[5-i] = *((uint8_t*)(f->value + 6 + i));
         }
      }
      else {
         for(i=0; i<6; i++){
            nf2_mask_p->entry.eth_dst[i] = 0;
         }
      }
   }
   else if (field == OFPXMT_OFB_IPV4_DST){
      nf2_entry_p->entry.ip_dst = ntohl(*((uint32_t*) f->value));
      if (OXM_HASMASK(f->header))nf2_mask_p->entry.ip_dst = ntohl(*((uint32_t*) (f->value + 4)));
      else nf2_mask_p->entry.ip_dst = 0;
   }                                                 
   else if (field == OFPXMT_OFB_IPV4_SRC){
      nf2_entry_p->entry.ip_src = ntohl(*((uint32_t*) f->value));
      if (OXM_HASMASK(f->header))nf2_mask_p->entry.ip_src = ntohl(*((uint32_t*) (f->value + 4)));    
      else nf2_mask_p->entry.ip_src = 0;
   
   }
   else if (field == OFPXMT_OFB_IP_PROTO){
      nf2_entry_p->entry.ip_proto = *((uint8_t*) f->value);
      nf2_mask_p->entry.ip_proto = 0; 
   } 
   else if (field == OFPXMT_OFB_IP_DSCP){   
      nf2_entry_p->entry.ip_tos |= (*((uint8_t*) f->value)) << 2;
      nf2_mask_p->entry.ip_tos &= 0x3; 
   } 
   else if (field == OFPXMT_OFB_IP_ECN){   
      nf2_entry_p->entry.ip_tos |= (*((uint8_t*) f->value));
      nf2_mask_p->entry.ip_tos &= 0xfc; 
   } 
   else if (field == OFPXMT_OFB_ICMPV4_TYPE){     
   } 
   else if (field == OFPXMT_OFB_ICMPV4_CODE){   
   }   
   else if (field == OFPXMT_OFB_ARP_SHA){   
   }
   else if (field == OFPXMT_OFB_ARP_THA){
   }                      
   else if (field == OFPXMT_OFB_ARP_SPA){
   } 
   else if (field == OFPXMT_OFB_ARP_TPA){
   } 
   else if (field == OFPXMT_OFB_ARP_OP){
   }
   else if (field == OFPXMT_OFB_IPV6_SRC){        
   }
   else if (field == OFPXMT_OFB_IPV6_DST){            
   }
   else if (field == OFPXMT_OFB_IPV6_ND_TARGET){          
   }  
   else if (field == OFPXMT_OFB_IPV6_ND_SLL){      
   }
   else if (field == OFPXMT_OFB_IPV6_ND_TLL){   
   }
   else if (field == OFPXMT_OFB_IPV6_FLABEL){      
   }
   else if (field == OFPXMT_OFB_ICMPV6_TYPE){
   } 
   else if (field == OFPXMT_OFB_ICMPV6_CODE){   
   }
   else if (field == OFPXMT_OFB_MPLS_LABEL){
   }
   else if (field == OFPXMT_OFB_MPLS_TC){
   }
   else if (field == OFPXMT_OFB_MPLS_BOS){
   }                  
   else if (field == OFPXMT_OFB_METADATA){ 
   }
   else if (field == OFPXMT_OFB_PBB_ISID ){
   }
   else if (field == OFPXMT_OFB_TUNNEL_ID){                                                           
   }
   else if (field == OFPXMT_OFB_IPV6_EXTHDR){
   }
}

void
ofl_instruction_2_nf2(struct ofl_instruction_header *inst, nf2_of_action_wrap *nf2_action_p) {
    switch(inst->type) {
        case (OFPIT_GOTO_TABLE): {
            struct ofl_instruction_goto_table *i = (struct ofl_instruction_goto_table*)inst;
            break;
        }
        case (OFPIT_WRITE_METADATA): {
            struct ofl_instruction_write_metadata *i = (struct ofl_instruction_write_metadata *)inst;
            break;
        }
        case (OFPIT_WRITE_ACTIONS):
        case (OFPIT_APPLY_ACTIONS): {
            struct ofl_instruction_actions *i = (struct ofl_instruction_actions *)inst;
            size_t j;

            for(j=0; j<i->actions_num; j++)
                ofl_action_2_nf2(i->actions[j], nf2_action_p);

            break;
        }
        case (OFPIT_CLEAR_ACTIONS): {
            break;
        }
        case (OFPIT_METER):{
            struct ofl_instruction_meter *i = (struct ofl_instruction_meter *)inst;
            break;
        }
        case (OFPIT_EXPERIMENTER): {
 
                 
            
            
            break;
        }
    }
}

void
set_forward_bitmask(nf2_of_action_wrap *nf2_action_p, uint32_t port){
    switch (port) {
        case (OFPP_IN_PORT): { return; }
        case (OFPP_TABLE): { return; }
        case (OFPP_NORMAL): { return; }
        case (OFPP_FLOOD): 
        case (OFPP_ALL): { 
            nf2_action_p->action.forward_bitmask |= 0x55;
            nf2_action_p->action.nf2_action_flag|= NF2_OFPAT_OUTPUT;
            return; 
        }
        case (OFPP_CONTROLLER): { return; }
        case (OFPP_LOCAL): { return; }
        case (OFPP_ANY): { return; }
        default: { 
           nf2_action_p->action.forward_bitmask |= (uint16_t)pow(2,(port-1)*2); //assume ports are labeled 1,2,3,4
           nf2_action_p->action.nf2_action_flag|= NF2_OFPAT_OUTPUT;
           return; 
        }
    }
}

void
ofl_action_2_nf2(struct ofl_action_header *act, nf2_of_action_wrap *nf2_action_p) {

    switch (act->type) {
        case OFPAT_OUTPUT: {
            struct ofl_action_output *a = (struct ofl_action_output *)act;
            set_forward_bitmask(nf2_action_p, a->port);
            break;
        }
        case OFPAT_SET_FIELD:{
            struct ofl_action_set_field *a = (struct ofl_action_set_field *)act;
 
            parse_oxm_tlv_action(a->field, nf2_action_p);

            break;
        }
        case OFPAT_COPY_TTL_OUT:
        case OFPAT_COPY_TTL_IN: {
            break;
        }
        case OFPAT_SET_MPLS_TTL: {
            struct ofl_action_mpls_ttl *a = (struct ofl_action_mpls_ttl *)act;
            break;
        }
        case OFPAT_DEC_MPLS_TTL: {
            break;
        }
        case OFPAT_PUSH_VLAN:
        case OFPAT_PUSH_MPLS:
        case OFPAT_PUSH_PBB:{
            break;
        }
        case OFPAT_POP_VLAN: {
            nf2_action_p->action.nf2_action_flag|= NF2_OFPAT_STRIP_VLAN;
            break;
        }
        case OFPAT_POP_PBB: {
            break;
        }
        case OFPAT_POP_MPLS: {
            break;
        }
        case OFPAT_SET_QUEUE: {
            break;
        }
        case OFPAT_GROUP: {
            break;
        }
        case OFPAT_SET_NW_TTL: {
            break;
        }
        case OFPAT_DEC_NW_TTL: {
            break;
        }
        case OFPAT_EXPERIMENTER: {
            break;
        }
    }
}

void 
parse_oxm_tlv_action(  struct ofl_match_tlv *f, nf2_of_action_wrap *nf2_action_p) {

   size_t i;

   uint8_t field = OXM_FIELD(f->header);

   if (field == OFPXMT_OFB_IN_PORT){
   }
   else if (field == OFPXMT_OFB_IN_PHY_PORT){
   }
   else if (field == OFPXMT_OFB_VLAN_VID){
      uint16_t *v = (uint16_t *) f->value;
      if (*v == OFPVID_NONE){}
         //printf( "vlan_vid= none");
      else if (*v == OFPVID_PRESENT && OXM_HASMASK(f->header)){}
         //printf( "vlan_vid= any");
      else {
         nf2_action_p->action.vlan_id = (*v & VLAN_VID_MASK);   
         nf2_action_p->action.nf2_action_flag |= NF2_OFPAT_SET_VLAN_VID;
      }
   }
   else if (field == OFPXMT_OFB_VLAN_PCP){
      nf2_action_p->action.vlan_pcp = (*f->value) & 0x7;   
         nf2_action_p->action.nf2_action_flag |= NF2_OFPAT_SET_VLAN_PCP;
   } 
   else if (field == OFPXMT_OFB_ETH_TYPE){
   }
   else if (field == OFPXMT_OFB_TCP_SRC || field == OFPXMT_OFB_UDP_SRC || field == OFPXMT_OFB_SCTP_SRC){
      nf2_action_p->action.transp_src = *((uint16_t*) f->value);
      nf2_action_p->action.nf2_action_flag |= NF2_OFPAT_SET_TP_SRC;
   }
   else if (field == OFPXMT_OFB_TCP_DST || field == OFPXMT_OFB_UDP_DST || field == OFPXMT_OFB_SCTP_DST){
      nf2_action_p->action.transp_dst = *((uint16_t*) f->value);
      nf2_action_p->action.nf2_actio_flag |= NF2_OFPAT_SET_TP_DST;
   }
   else if (field == OFPXMT_OFB_ETH_SRC){
      for(i=0; i<6; i++){
         nf2_action_p->action.eth_src[5-i] = *((uint8_t*)(f->value + i));
      }                            
      nf2_action_p->action.nf2_action_flag |= NF2_OFPAT_SET_DL_SRC;
      }
   
   else if (field == OFPXMT_OFB_ETH_DST){
      for(i=0; i<6; i++){
        nf2_action_p->action.eth_dst[5-i] = *((uint8_t*)(f->value + i));
      }
      nf2_action_p->action.nf2_action_flag |= NF2_OFPAT_SET_DL_DST;
   }
   else if (field == OFPXMT_OFB_IPV4_DST){
      nf2_action_p->action.ip_dst = ntohl(*((uint32_t*) f->value));
      nf2_action_p->action.nf2_action_flag |= NF2_OFPAT_SET_NW_DST;
   }                                                 
   else if (field == OFPXMT_OFB_IPV4_SRC){
      nf2_action_p->action.ip_src = ntohl(*((uint32_t*) f->value));
      nf2_action_p->action.nf2_action_flag |= NF2_OFPAT_SET_NW_SRC;
   }
   else if (field == OFPXMT_OFB_IP_PROTO){
   } 
   else if (field == OFPXMT_OFB_IP_DSCP){      
      nf2_action_p->action.ip_tos |= (*((uint8_t*) f->value)) << 2;
      nf2_action_p->action.nf2_action_flag |= NF2_OFPAT_SET_NW_TOS;
   } 
   else if (field == OFPXMT_OFB_IP_ECN){   
      nf2_action_p->action.ip_tos |= *((uint8_t*) f->value);
      nf2_action_p->action.nf2_action_flag |= NF2_OFPAT_SET_NW_TOS;
   } 
   else if (field == OFPXMT_OFB_ICMPV4_TYPE){     
   } 
   else if (field == OFPXMT_OFB_ICMPV4_CODE){   
   }   
   else if (field == OFPXMT_OFB_ARP_SHA){   
   }
   else if (field == OFPXMT_OFB_ARP_THA){
   }                      
   else if (field == OFPXMT_OFB_ARP_SPA){
   } 
   else if (field == OFPXMT_OFB_ARP_TPA){
   } 
   else if (field == OFPXMT_OFB_ARP_OP){
   }
   else if (field == OFPXMT_OFB_IPV6_SRC){        
   }
   else if (field == OFPXMT_OFB_IPV6_DST){            
   }
   else if (field == OFPXMT_OFB_IPV6_ND_TARGET){          
   }  
   else if (field == OFPXMT_OFB_IPV6_ND_SLL){      
   }
   else if (field == OFPXMT_OFB_IPV6_ND_TLL){   
   }
   else if (field == OFPXMT_OFB_IPV6_FLABEL){      
   }
   else if (field == OFPXMT_OFB_ICMPV6_TYPE){
   } 
   else if (field == OFPXMT_OFB_ICMPV6_CODE){   
   }
   else if (field == OFPXMT_OFB_MPLS_LABEL){
   }
   else if (field == OFPXMT_OFB_MPLS_TC){
   }
   else if (field == OFPXMT_OFB_MPLS_BOS){
   }                  
   else if (field == OFPXMT_OFB_METADATA){ 
   }
   else if (field == OFPXMT_OFB_PBB_ISID ){
   }
   else if (field == OFPXMT_OFB_TUNNEL_ID){
   }
   else if (field == OFPXMT_OFB_IPV6_EXTHDR){
   }
}


