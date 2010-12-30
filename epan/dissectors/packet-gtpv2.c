/* packet-gtpv2.c
 *
 * Routines for GTPv2 dissection
 * Copyright 2009 - 2010, Anders Broman <anders.broman [at] ericcsson.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * Ref: 3GPP TS 29.274 version 8.1.1 Release 8 ETSI TS 129 274 V8.1.1 (2009-04)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/sminmpec.h>

#include "packet-gsm_a_common.h"
#include "packet-gsm_map.h"
#include "packet-e164.h"
#include "packet-e212.h"
#include "packet-s1ap.h"
#include "packet-ranap.h"


static dissector_handle_t nas_eps_handle;

/*GTPv2 Message->GTP Header(SB)*/
static int proto_gtpv2 = -1;
static int hf_gtpv2_flags = -1;
static int hf_gtpv2_version = -1;
static int hf_gtpv2_p = -1;
static int hf_gtpv2_t = -1;
static int hf_gtpv2_message_type = -1;
static int hf_gtpv2_msg_length = -1;
static int hf_gtpv2_teid = -1;
static int hf_gtpv2_seq = -1;
static int hf_gtpv2_spare = -1;


static int hf_gtpv2_ie = -1;
static int hf_gtpv2_ie_len = -1;
static int hf_gtpv2_cr = -1;
static int hf_gtpv2_instance = -1;
static int hf_gtpv2_cause = -1;
static int hf_gtpv2_cause_cs = -1;
static int hf_gtpv2_rec = -1;
static int hf_gtpv2_apn = -1;
static int hf_gtpv2_ebi = -1;
static int hf_gtpv2_daf = -1;
static int hf_gtpv2_dtf = -1;
static int hf_gtpv2_hi = -1;
static int hf_gtpv2_dfi = -1;
static int hf_gtpv2_oi = -1;
static int hf_gtpv2_isrsi = -1;
static int hf_gtpv2_israi = -1;
static int hf_gtpv2_sgwci = -1;
static int hf_gtpv2_pt = -1;
static int hf_gtpv2_tdi = -1;
static int hf_gtpv2_si = -1;
static int hf_gtpv2_msv = -1;
static int hf_gtpv2_pdn_type = -1;
static int hf_gtpv2_pdn_ipv4 = -1;
static int hf_gtpv2_pdn_ipv6_len = -1;
static int hf_gtpv2_pdn_ipv6 = -1;


static int hf_gtpv2_rat_type = -1;
static int hf_gtpv2_uli_ecgi_flg = -1;
static int hf_gtpv2_uli_tai_flg = -1;
static int hf_gtpv2_uli_rai_flg = -1;
static int hf_gtpv2_uli_sai_flg = -1;
static int hf_gtpv2_uli_cgi_flg = -1;
static int hf_gtpv2_cng_rep_act = -1;

static gint ett_gtpv2 = -1;
static gint ett_gtpv2_flags = -1;
static gint ett_gtpv2_ie = -1;
static gint ett_gtpv2_bearer_ctx = -1;
static gint ett_gtpv2_PDN_conn = -1;

static int hf_gtpv2_selec_mode= -1;

static int hf_gtpv2_f_teid_v4= -1;
static int hf_gtpv2_f_teid_v6= -1;
static int hf_gtpv2_f_teid_interface_type= -1;
static int hf_gtpv2_f_teid_gre_key= -1;
static int hf_gtpv2_f_teid_ipv4= -1;
static int hf_gtpv2_f_teid_ipv6= -1;
static int hf_gtpv2_hsgw_addr_f_len = -1;
static int hf_gtpv2_imsi= -1;

static int hf_gtpv2_ambr_up= -1;
static int hf_gtpv2_ambr_down= -1;
static int hf_gtpv2_ip_address_ipv4= -1;
static int hf_gtpv2_ip_address_ipv6= -1;
static int hf_gtpv2_mei= -1;
static int hf_gtpv2_address_digits = -1;
static int hf_gtpv2_ti = -1;

static int hf_gtpv2_bearer_qos_pvi= -1;
static int hf_gtpv2_bearer_qos_pl= -1;
static int hf_gtpv2_bearer_qos_pci= -1;
static int hf_gtpv2_bearer_qos_label_qci= -1;
static int hf_gtpv2_bearer_qos_mbr_up= -1;
static int hf_gtpv2_bearer_qos_mbr_down= -1;
static int hf_gtpv2_bearer_qos_gbr_up= -1;
static int hf_gtpv2_bearer_qos_gbr_down= -1;
static int hf_gtpv2_flow_qos_label_qci= -1;
static int hf_gtpv2_flow_qos_mbr_up= -1;
static int hf_gtpv2_flow_qos_mbr_down= -1;
static int hf_gtpv2_flow_qos_gbr_up= -1;
static int hf_gtpv2_flow_qos_gbr_down= -1;

static int hf_gtpv2_delay_value= -1;
static int hf_gtpv2_charging_id= -1;
static int hf_gtpv2_charging_characteristic= -1;
static int hf_gtpv2_bearer_flag= -1;
static int hf_gtpv2_ue_time_zone= -1;
static int hf_gtpv2_ue_time_zone_dst= -1;
static int hf_gtpv2_complete_req_msg_type = -1;
static int hf_gtpv2_mme_grp_id = -1;
static int hf_gtpv2_mme_code = -1;
static int hf_gtpv2_m_tmsi = -1;
static int hf_gtpv2_container_type = -1;
static int hf_gtpv2_cause_type = -1;
static int hf_gtpv2_CauseRadioNetwork = -1;
static int hf_gtpv2_CauseTransport = -1;
static int hf_gtpv2_CauseNas = -1;
static int hf_gtpv2_CauseProtocol = -1;
static int hf_gtpv2_CauseMisc = -1;
static int hf_gtpv2_target_type = -1;
static int hf_gtpv2_macro_enodeb_id = -1;

static int hf_gtpv2_node_type= -1;
static int hf_gtpv2_enterprise_id = -1;
static int hf_gtpv2_apn_rest= -1;
static int hf_gtpv2_pti= -1;
static int hf_gtpv2_uli_cgi_lac= -1;
static int hf_gtpv2_uli_cgi_ci= -1;
static int hf_gtpv2_uli_sai_lac= -1;
static int hf_gtpv2_uli_sai_sac= -1;
static int hf_gtpv2_uli_rai_lac= -1;
static int hf_gtpv2_uli_rai_rac= -1;
static int hf_gtpv2_uli_tai_tac= -1;
static int hf_gtpv2_uli_ecgi_eci= -1;
static int hf_gtpv2_uli_ecgi_eci_spare= -1;
static int hf_gtpv2_bearer_control_mode= -1;

/* Definition of User Location Info (AVP 22) masks */
#define GTPv2_ULI_CGI_MASK			0x01
#define GTPv2_ULI_SAI_MASK			0x02
#define GTPv2_ULI_RAI_MASK			0x04
#define GTPv2_ULI_TAI_MASK			0x08
#define GTPv2_ULI_ECGI_MASK			0x10

#define GTPV2_FORWARD_RELOCATION_REQ	133
#define GTPV2_FORWARD_CTX_NOTIFICATION	137
static void dissect_gtpv2_ie_common(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint offset, guint8 message_type);

/*Message Types for GTPv2 (Refer Pg19 29.274) (SB)*/
static const value_string gtpv2_message_type_vals[] = {
    {0, "Reserved"},
    {1, "Echo Request"},
    {2, "Echo Response"},
    {3, "Version Not Supported Indication"},
    /* 4-24 Reserved for S101 interface TS 29.276 */
    /* 25-31 Reserved for Sv interface TS 29.280 */
    /* SGSN/MME to PGW (S4/S11, S5/S8) */
    {32, "Create Session Request"},
    {33, "Create Session Response"},
    {34, "Modify Bearer Request"},
    {35, "Modify Bearer Response"},
    {36, "Delete Session Request"},
    {37, "Delete Session Response"},
    /* SGSN to PGW (S4, S5/S8) */
    {38, "Change Notification Request"},
    {39, "Change Notification Response"},
    /* 40-63 For future use */
    /* Messages without explicit response */
    {64, "Modify Bearer Command"},                          /* (MME/SGSN to PGW -S11/S4, S5/S8) */
    {65, "Modify Bearer Failure Indication"},               /*(PGW to MME/SGSN -S5/S8, S11/S4) */
    {66, "Delete Bearer Command"},                          /* (MME to PGW -S11, S5/S8) */
    {67, "Delete Bearer Failure Indication"},               /* (PGW to MME -S5/S8, S11) */
    {68, "Bearer Resource Command"},                        /* (MME/SGSN to PGW -S11/S4, S5/S8) */
    {69, "Bearer Resource Failure Indication"},             /* (PGW to MME/SGSN -S5/S8, S11/S4) */
    {70, "Downlink Data Notification Failure Indication"},  /*(SGSN/MME to SGW -S4/S11) */
    {71, "Trace Session Activation"},
    {72, "Trace Session Deactivation"},
    {73, "Stop Paging Indication"},
    /* 74-94 For future use */
    /* PDN-GW to SGSN/MME (S5/S8, S4/S11) */
    {95, "Create Bearer Request"},
    {96, "Create Bearer Response"},
    {97, "Update Bearer Request"},
    {98, "Update Bearer Response"},
    {99, "Delete Bearer Request"},
    {100, "Delete Bearer Response"},
    /* PGW to MME, MME to PGW, SGW to PGW, SGW to MME (S5/S8, S11) */
    {101, "Delete PDN Connection Set Request"},
    {102, "Delete PDN Connection Set Response"},
    /* 103-127 For future use */
    /* MME to MME, SGSN to MME, MME to SGSN, SGSN to SGSN (S3/10/S16) */
    {128, "Identification Request"},
    {129, "Identification Response"},
    {130, "Context Request"},
    {131, "Context Response"},
    {132, "Context Acknowledge"},
    {133, "Forward Relocation Request"},
    {134, "Forward Relocation Response"},
    {135, "Forward Relocation Complete Notification"},
    {136, "Forward Relocation Complete Acknowledge"},
    {137, "Forward Access Context Notification"},
    {138, "Forward Access Context Acknowledge"},
    {139, "Relocation Cancel Request"},
    {140, "Relocation Cancel Response"},
    {141, "Configuration Transfer Tunnel"},
    /* 142-148 For future use */
    /* SGSN to MME, MME to SGSN (S3)*/
    {149, "Detach Notification"},
    {150, "Detach Acknowledge"},
    {151, "CS Paging Indication"},
    {152, "RAN Information Relay"},
    {153, "Alert MME Notification"},
    {154, "Alert MME Acknowledge"},
    {155, "UE Activity Notification"},
    {156, "UE Activity Acknowledge"},
    /* 157 to 159 For future use */
    /* MME to SGW (S11) */
    {160, "Create Forwarding Tunnel Request"},
    {161, "Create Forwarding Tunnel Response"},
    {162, "Suspend Notification"},
    {163, "Suspend Acknowledge"},
    {164, "Resume Notification"},
    {165, "Resume Acknowledge"},
    {166, "Create Indirect Data Forwarding Tunnel Request"},
    {167, "Create Indirect Data Forwarding Tunnel Response"},
    {168, "Delete Indirect Data Forwarding Tunnel Request"},
    {169, "Delete Indirect Data Forwarding Tunnel Response"},
    {170, "Release Access Bearers Request"},
    {171, "Release Access Bearers Response"},
    /* 172-175 For future use */
    /* SGW to SGSN/MME (S4/S11) */
    {176, "Downlink Data Notification"},
    {177, "Downlink Data Notification Acknowledgement"},
    /* SGW to SGSN (S4) */
    {178, "Update Bearer Complete"},
    /* 179-191 For future use */
    /* Other */
    {200, "Update PDN Connection Set Request"},
    {201, "Update PDN Connection Set Response"},
	/* 202 to 230 For future use */
	/* MBMS GW to MME/SGSN (Sm/Sn) */
    {231, "MBMS Session Start Request"},
    {323, "MBMS Session Start Response"},
    {233, "MBMS Session Update Request"},
    {234, "MBMS Session Update Response"},
    {235, "MBMS Session Stop Request"},
    {236, "MBMS Session Stop Response"},
	/* 237 to 239 For future use */
/* 240-255 Reserved for GTP-U TS 29.281 [13] */
    {0, NULL}
};

#define GTPV2_IE_RESERVED        0
#define GTPV2_IE_IMSI            1
#define GTPV2_IE_CAUSE           2
#define GTPV2_REC_REST_CNT       3
#define GTPV2_APN               71
#define GTPV2_AMBR              72
#define GTPV2_EBI               73
#define GTPV2_IP_ADDRESS        74
#define GTPV2_MEI               75
#define GTPV2_IE_MSISDN         76
#define GTPV2_INDICATION        77
#define GTPV2_PCO               78
#define GTPV2_PAA               79
#define GTPV2_BEARER_QOS        80
#define GTPV2_IE_FLOW_QOS       81
#define GTPV2_IE_RAT_TYPE       82
#define GTPV2_IE_SERV_NET       83
#define GTPV2_BEARER_TFT        84
#define GTPV2_IE_TAD            85
#define GTPV2_IE_ULI            86
#define GTPV2_IE_F_TEID         87
#define GTPV2_IE_GLOBAL_CNID    89
#define GTPV2_IE_S103PDF        90
#define GTPV2_IE_DEL_VAL        92
#define GTPV2_IE_BEARER_CTX     93
#define GTPV2_IE_CHAR_ID        94
#define GTPV2_IE_CHAR_CHAR      95
#define GTPV2_BEARER_FLAG       97
#define GTPV2_IE_PDN_TYPE       99
#define GTPV2_IE_PTI            100
#define GTPV2_PDN_CONN			109
#define GTPV2_IE_UE_TIME_ZONE   114
#define GTPV2_IE_COMPLETE_REQUEST_MSG	116
#define GTPV2_IE_GUTI           117
#define GTPV2_IE_F_CONTAINER	118
#define GTPV2_IE_F_CAUSE		119
#define GTPV2_TARGET_ID			121
#define GTPV2_APN_RESTRICTION   127
#define GTPV2_SELEC_MODE        128
#define GTPV2_BEARER_CONTROL_MODE   130
#define GTPV2_CNG_REP_ACT       131
#define GTPV2_NODE_TYPE         135
#define GTPV2_FQDN				136
#define GTPV2_TI				137
#define GTPV2_PRIVATE_EXT       255

#define SPARE                               0X0
#define CREATE_NEW_TFT                      0X20
#define DELETE_TFT                          0X40
#define ADD_PACKET_FILTERS_TFT              0X60
#define REPLACE_PACKET_FILTERS_TFT          0X80
#define DELETE_PACKET_FILTERS_TFT           0XA0
#define NO_TFT_OPERATION                    0XC0
#define RESERVED                            0XE0


/* Table 8.1-1: Information Element types for GTPv2 */
static const value_string gtpv2_element_type_vals[] = {
    {0, "Reserved"},
    {1, "International Mobile Subscriber Identity (IMSI)"},                     /* Variable Length / 8.3 */
    {2, "Cause"},                                                               /* Variable Length / 8.4 */
    {3, "Recovery (Restart Counter)"},                                          /* Variable Length / 8.5 */
    /* 4-50 Reserved for S101 interface Extendable / See 3GPP TS 29.276 [14] */
    /* 51-70 Reserved for Sv interface Extendable / See 3GPP TS 29.280 [15] */
    {71, "Access Point Name (APN)"},                                            /* Variable Length / 8.6 */
    {72, "Aggregate Maximum Bit Rate (AMBR)"},                                  /* Fixed Length / 8.7 */
    {73, "EPS Bearer ID (EBI)"},                                                /* Extendable / 8.8 */
    {74, "IP Address"},                                                         /* Extendable / 8.9 */
    {75, "Mobile Equipment Identity (MEI)"},                                    /* Variable Length / 8.10 */
    {76, "MSISDN"},                                                             /* Variable Length / 8.11 */
    {77, "Indication"},                                                         /* Extendable / 8.12 */
    {78, "Protocol Configuration Options (PCO)"},                               /* Variable Length / 8.13 */
    {79, "PDN Address Allocation (PAA)"},                                       /* Variable Length / 8.14 */
    {80, "Bearer Level Quality of Service (Bearer QoS)"},                       /* Variable Length / 8.15 */
    {81, "Flow Quality of Service (Flow QoS)"},                                 /* Extendable / 8.16 */
    {82, "RAT Type"},                                                           /* Extendable / 8.17 */
    {83, "Serving Network"},                                                    /* Extendable / 8.18 */
    {84, "EPS Bearer Level Traffic Flow Template (Bearer TFT)"},                /* Variable Length / 8.19 */
    {85, "Traffic Aggregation Description (TAD)"},                              /* Variable Length / 8.20 */
    {86, "User Location Info (ULI)"},                                           /* Variable Length / 8.21 */
    {87, "Fully Qualified Tunnel Endpoint Identifier (F-TEID)"},                /* Extendable / 8.22 */
    {88, "TMSI"},                                                               /* Variable Length / 8.23 */
    {89, "Global CN-Id"},                                                       /* Variable Length / 8.24 */
    {90, "S103 PDN Data Forwarding Info (S103PDF)"},                            /* Variable Length / 8.25 */
    {91, "S1-U Data Forwarding Info (S1UDF)"},                                  /* Variable Length/ 8.26 */
    {92, "Delay Value"},                                                        /* Extendable / 8.27 */
    {93, "Bearer Context"},                                                     /* Extendable / 8.28 */
    {94, "Charging ID"},                                                        /* Extendable / 8.29 */
    {95, "Charging Characteristics"},                                           /* Extendable / 8.30 */
    {96, "Trace Information"},                                                  /* Extendable / 8.31 */
    {97, "Bearer Flags"},                                                       /* Extendable / 8.32 */
    {98, "Paging Cause"},                                                       /* Variable Length / 8.33 */
    {99, "PDN Type"},                                                           /* Extendable / 8.34 */
    {100, "Procedure Transaction ID"},                                          /* Extendable / 8.35 */
    {101, "DRX Parameter"},                                                     /* Variable Length/ 8.36 */
    {102, "UE Network Capability"},                                             /* Variable Length / 8.37 */
    {103, "MM Context (GSM Key and Triplets)"},                                 /* Variable Length / 8.38 */
    {104, "MM Context (UMTS Key, Used Cipher and Quintuplets)"},                /* Variable Length / 8.38 */
    {105, "MM Context (GSM Key, Used Cipher and Quintuplets)"},                 /* Variable Length / 8.38 */
    {106, "MM Context (UMTS Key and Quintuplets)"},                             /* Variable Length / 8.38 */
    {107, "MM Context (EPS Security Context, Quadruplets and Quintuplets)"},    /* Variable Length / 8.38 */
    {108, "MM Context (UMTS Key, Quadruplets and Quintuplets)"},                /* Variable Length / 8.38 */
    {109, "PDN Connection"},                                                    /* Extendable / 8.39 */
    {110, "PDU Numbers"},                                                       /* Extendable / 8.40 */
    {111, "P-TMSI"},                                                            /* Variable Length / 8.41 */
    {112, "P-TMSI Signature"},                                                  /* Variable Length / 8.42 */
    {113, "Hop Counter"},                                                       /* Extendable / 8.43 */
    {114, "UE Time Zone"},                                                      /* Variable Length / 8.44 */
    {115, "Trace Reference"},                                                   /* Fixed Length / 8.45 */
    {116, "Complete Request Message"},                                          /* Variable Length / 8.46 */
    {117, "GUTI"},                                                              /* Variable Length / 8.47 */
    {118, "F-Container"},                                                       /* Variable Length / 8.48 */
    {119, "F-Cause"},                                                           /* Variable Length / 8.49 */
    {120, "Selected PLMN ID"},                                                  /* Variable Length / 8.50 */
    {121, "Target Identification"},                                             /* Variable Length / 8.51 */
    {122, "NSAPI"},                                                             /* Extendable / 8.52 */
    {123, "Packet Flow ID"},                                                    /* Variable Length / 8.53 */
    {124, "RAB Context"},                                                       /* Fixed Length / 8.54 */
    {125, "Source RNC PDCP Context Info"},                                      /* Variable Length / 8.55 */
    {126, "UDP Source Port Number"},                                            /* Extendable / 8.56 */
    {127, "APN Restriction"},                                                   /* Extendable / 8.57 */
    {128, "Selection Mode"},                                                    /* Extendable / 8.58 */
    {129, "Source Identification"},                                             /* Variable Length / 8.50 */
    {130, "Bearer Control Mode"},                                               /* Extendable / 8.60 */
    {131, "Change Reporting Action"},                                           /* Variable Length / 8.61 */
    {132, "Fully Qualified PDN Connection Set Identifier (FQ-CSID)"},           /* Variable Length / 8.62 */
    {133, "Channel needed"},                                                    /* Extendable / 8.63 */
    {134, "eMLPP Priority"},                                                    /* Extendable / 8.64 */
    {135, "Node Type"},                                                         /* Extendable / 8.65 */
    {136, "Fully Qualified Domain Name (FQDN)"},                                /* Variable Length / 8.66 */
    {137, "Transaction Identifier (TI)"},                                       /* Variable Length / 8.68 */
    {138, "MBMS Session"},														/* Duration Extendable / 8.69 */
    {139, "MBMS Service Area"},													/* Extendable / 8.70 */
    {140, "MBMS Session Identifier"},											/* Extendable / 8.71 */
    {141, "MBMS Flow Identifier"},												/* Extendable / 8.72 */
    {142, "MBMS IP Multicast Distribution"},									/* Extendable / 8.73 */
    {143, "MBMS Distribution Acknowledge"},										/* Extendable / 8.74 */
    {144, "RFSP Index"},														/* Fixed Length / 8.77 */
    {145, "User CSG Information (UCI)"},										/* Extendable / 8.75 */
    {146, "CSG Information Reporting Action"},									/* Extendable / 8.76 */
    {147, "CSG ID"},															/* Extendable / 8.78 */
    {148, "CSG Membership Indication (CMI)"},									/* Extendable / 8.79 */
    /* 149 to 254 Spare. For future use.  */                                    /* For future use. FFS */
    {255, "Private"},                                                           /* Extension Extendable / 8.67 */
    {0, NULL}
};

/* Code to dissect IE's */

static void
dissect_gtpv2_unknown(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{

    proto_tree_add_text(tree, tvb, 0, length, "IE data not dissected yet");
}

/*
 * 8.3 International Mobile Subscriber Identity (IMSI)
 *
 * IMSI is defined in 3GPP TS 23.003
 * Editor's note: IMSI coding will be defined in 3GPP TS 24.301
 * Editor's note: In the first release of GTPv2 spec (TS 29.274v8.0.0) n = 8.
 * That is, the overall length of the IE is 11 octets.
 */

static void
dissect_gtpv2_imsi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    int offset= 0;
	tvbuff_t *tvb_new;
    const gchar *imsi_str;

	tvb_new = tvb_new_subset_remaining(tvb, offset);
    imsi_str = unpack_digits(tvb, offset);

    proto_tree_add_string(tree, hf_gtpv2_imsi, tvb, offset, length, imsi_str);
}

/* Table 8.4-1: Cause values */
static const value_string gtpv2_cause_vals[] = {
    {0, "Reserved"},
    /* Request */
    {1, "Paging Cause"},
    {2, "Local Detach"},
    {3, "Complete Detach"},
    {4, "RAT changed from 3GPP to Non-3GPP"},
    {5, "ISR is activated"},
    /* 6-15 Spare. This value range is reserved for Cause values in a request message */
    /* Acceptance Response */
    {16, "Request accepted"},
    {17, "Request accepted partially"},
    {18, "New PDN type due to network preference"},
    {19, "New PDN type due to single address bearer only"},
    /* 20-63 Spare. This value range is reserved for Cause values in acceptance response message */
    /* Rejection Response */
    {64, "Context Not Found"},
    {65, "Invalid Message Format"},
    {66, "Version not supported by next peer"},
    {67, "Invalid length"},
    {68, "Service not supported"},
    {69, "Mandatory IE incorrect"},
    {70, "Mandatory IE missing"},
    {71, "Optional IE incorrect"},
    {72, "System failure"},
    {73, "No resources available"},
    {74, "Semantic error in the TFT operation"},
    {75, "Syntactic error in the TFT operation"},
    {76, "Semantic errors in packet filter(s)"},
    {77, "Syntactic errors in packet filter(s)"},
    {78, "Missing or unknown APN"},
    {79, "Unexpected repeated IE"},
    {80, "GRE key not found"},
    {81, "Reallocation failure"},
    {82, "Denied in RAT"},
    {83, "Preferred PDN type not supported"},
    {84, "All dynamic addresses are occupied"},
    {85, "UE context without TFT already activated"},
    {86, "Protocol type not supported"},
    {87, "UE not responding"},
    {88, "UE refuses"},
    {89, "Service denied"},
    {90, "Unable to page UE"},
    {91, "No memory available"},
    {92, "User authentication failed"},
    {93, "APN access denied - no subscription"},
    {94, "Request rejected"},
    {95, "P-TMSI Signature mismatch"},
    {96, "IMSI not known"},
    {97, "Semantic error in the TAD operation"},
    {98, "Syntactic error in the TAD operation"},
    {99, "Reserved Message Value Received"},
    {100, "PGW not responding"},
    {101, "Collision with network initiated request"},
    {102, "Unable to page UE due to Suspension"},
    {103, "Conditional IE missing"},
    {104, "APN Restriction type Incompatible with currently active PDN connection"},
    /* 105-219 Spare. This value range is reserved for Cause values in rejection response message */
    /* 220-255 Reserved for 3GPP Specific PMIPv6 Error Codes as defined in 3GPP TS 29.275 [26] */
    {0, NULL}
};

/*
 * 8.4 Cause
 */

/* Table 8.4-1: CS (Cause Source) */
static const value_string gtpv2_cause_cs[] = {
    {0, "Originated by node sending the message"},
    {1, "Originated by remote node"},
    {0, NULL}
};

static void
dissect_gtpv2_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    int offset = 0;
    /* Cause value octet 5 */
    proto_tree_add_item(tree, hf_gtpv2_cause, tvb, offset, 1, FALSE);
    offset++;
    proto_tree_add_item(tree, hf_gtpv2_cause_cs, tvb, offset, 1, FALSE);
}

/*
 * 8.5 Recovery (Restart Counter)
 */
static void
dissect_gtpv2_recovery(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    int offset = 0;
    proto_tree_add_item(tree, hf_gtpv2_rec, tvb, offset, 1, FALSE);
}

/*
 * 8.6 Access Point Name (APN)
 */
static void
dissect_gtpv2_apn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    int offset = 0;
    guint8 *apn = NULL;
    int name_len, tmp;

    if (length > 0) {
        name_len = tvb_get_guint8(tvb, offset);

        if (name_len < 0x20) {
            apn = tvb_get_ephemeral_string(tvb, offset + 1, length - 1);
            for (;;) {
                if (name_len >= length - 1)
                break;
                tmp = name_len;
                name_len = name_len + apn[tmp] + 1;
                apn[tmp] = '.';
            }
        } else{
            apn = tvb_get_ephemeral_string(tvb, offset, length);
        }
        proto_tree_add_string(tree, hf_gtpv2_apn, tvb, offset, length, apn);
    }

}

/*
 * 8.7 Aggregate Maximum Bit Rate (AMBR) */

static void
dissect_gtpv2_ambr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    int offset = 0;
    proto_tree_add_item(tree, hf_gtpv2_ambr_up, tvb, offset, 4, FALSE);
    offset= offset + 4;
    proto_tree_add_item(tree, hf_gtpv2_ambr_down, tvb, offset, 4, FALSE);
}

/*
 * 8.8 EPS Bearer ID (EBI)
 */
static void
dissect_gtpv2_ebi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{

    int offset = 0;
    /* Spare (all bits set to 0) B8 - B5*/
    /* EPS Bearer ID (EBI) B4 - B1 */
    proto_tree_add_item(tree, hf_gtpv2_ebi, tvb, offset, 1, FALSE);

}
/* 8.9 IP Address  */
static void
dissect_gtpv2_ip_address(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    int offset = 0;
    if (length==4)
    {
        proto_tree_add_item(tree, hf_gtpv2_ip_address_ipv4, tvb, offset, length, FALSE);
    }
    else if (length==16)
    {
        proto_tree_add_item(tree, hf_gtpv2_ip_address_ipv6, tvb, offset, length, FALSE);
    }
}
/* 8.10 Mobile Equipment Identity (MEI)*/
static gchar *mei_to_str(const guint8 * ad)
{
    static gchar str[17] = "                ";
    int i, j = 0;
    for (i = 0; i < 8; i++)
    {
        if (((ad[i] >> 4) & 0x0F) <= 9)
            str[j++] = ((ad[i] >> 4) & 0x0F) + 0x30;
        if ((ad[i] & 0x0F) <= 9)
            str[j++] = (ad[i] & 0x0F) + 0x30; /* Adding 0x30(48 decimal) makes it a printable digit (Eg. Ascii value 0f 9 is 57 (9+48))*/
    }
    str[j] = '\0';
    return str;
}

static void
dissect_gtpv2_mei(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    int offset= 0;
    guint8 mei_val[8];
    gchar *mei_str;
    tvb_memcpy(tvb, mei_val, offset , 8);
    mei_str = mei_to_str(mei_val);
    proto_tree_add_string(tree, hf_gtpv2_mei, tvb, offset, length, mei_str);
}

/*
 * 8.11 MSISDN
 *
 * MSISDN is defined in 3GPP TS 23.003
 * Editor's note: MSISDN coding will be defined in TS 24.301.
 */
static void
dissect_gtpv2_msisdn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    const char     *digit_str;

    dissect_e164_cc(tvb, tree, 0, TRUE);
    digit_str = unpack_digits(tvb, 1);
    proto_tree_add_string(tree, hf_gtpv2_address_digits, tvb, 1, -1, digit_str);
}

/*
 * 8.12 Indication
 */
static void
dissect_gtpv2_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    int offset = 0;
    proto_tree_add_item(tree, hf_gtpv2_daf,         tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_gtpv2_dtf,         tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_gtpv2_hi,          tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_gtpv2_dfi,         tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_gtpv2_oi,          tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_gtpv2_isrsi,       tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_gtpv2_israi,       tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_gtpv2_sgwci,       tvb, offset, 1, FALSE);
    if(length==1)
    {
        proto_tree_add_text(tree, tvb, 0, length, "Older version?, should be 2 octets in 8.0.0");
        return;
    }
    offset++;
    proto_tree_add_item(tree, hf_gtpv2_pt,          tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_gtpv2_tdi,         tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_gtpv2_si,          tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_gtpv2_msv,         tvb, offset, 1, FALSE);
}

/*
 * 8.13 Protocol Configuration Options (PCO)
 * Editor's note: PCO will be defined in 3GPP TS 23.003 and its coding in TS 24.301
 * Dissected in packet-gsm_a_gm.c
 */
static void
dissect_gtpv2_pco(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    /* pinfo needed */
    gsm_a_dtap_pinfo = pinfo;
    de_sm_pco(tvb, tree, 0, length, NULL, 0);
}

/*
 * 8.14 PDN Address Allocation (PAA)
 */

static const value_string gtpv2_pdn_type_vals[] = {
    {1, "IPv4"},
    {2, "IPv6"},
    {3, "IPv4/IPv6"},
    {0, NULL}
};

static void
dissect_gtpv2_paa(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    int offset = 0;
    guint8 pdn_type;
    pdn_type  = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_gtpv2_pdn_type, tvb, offset, 1, FALSE);
    offset++;
    switch(pdn_type)
    {
    case 1:
        /* IPv4 */
        proto_tree_add_item(tree, hf_gtpv2_pdn_ipv4, tvb, offset, 4, FALSE);
        offset+=4;
        break;
    case 2:
        /* IPv6*/
        proto_tree_add_item(tree, hf_gtpv2_pdn_ipv6_len, tvb, offset, 1, FALSE);
        offset++;
        proto_tree_add_item(tree, hf_gtpv2_pdn_ipv6, tvb, offset, 16, FALSE);
        offset+=16;
        break;
    case 3:
        /* IPv4/IPv6 */
        proto_tree_add_item(tree, hf_gtpv2_pdn_ipv6_len, tvb, offset, 1, FALSE);
        offset++;
        proto_tree_add_item(tree, hf_gtpv2_pdn_ipv6, tvb, offset, 16, FALSE);
        offset+=16;
        proto_tree_add_item(tree, hf_gtpv2_pdn_ipv4, tvb, offset, 4, FALSE);
        offset+=4;
        break;
    default:
        break;
    }
}
/*
 * 8.15 Bearer Quality of Service (Bearer QoS)
 */

static void
dissect_gtpv2_bearer_qos(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    int offset = 0;
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_pvi, tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_pl, tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_pci, tvb, offset, 1, FALSE);
    offset++;
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_label_qci, tvb, offset, 1, FALSE);
    offset++;
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_mbr_up, tvb, offset, 5, FALSE);
    offset= offset+5;
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_mbr_down, tvb, offset, 5, FALSE);
    offset= offset+5;
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_gbr_up, tvb, offset, 5, FALSE);
    offset= offset+5;
    proto_tree_add_item(tree, hf_gtpv2_bearer_qos_gbr_down, tvb, offset, 5, FALSE);
    offset= offset+5;
}

/*
 * 8.16 Flow Quality of Service (Flow QoS)
 */

static void
dissect_gtpv2_flow_qos(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    int offset = 0;
    proto_tree_add_item(tree, hf_gtpv2_flow_qos_label_qci, tvb, offset, 1, FALSE);
    offset++;
    proto_tree_add_item(tree, hf_gtpv2_flow_qos_mbr_up, tvb, offset, 5, FALSE);
    offset= offset+5;
    proto_tree_add_item(tree, hf_gtpv2_flow_qos_mbr_down, tvb, offset, 5, FALSE);
    offset= offset+5;
    proto_tree_add_item(tree, hf_gtpv2_flow_qos_gbr_up, tvb, offset, 5, FALSE);
    offset= offset+5;
    proto_tree_add_item(tree, hf_gtpv2_flow_qos_gbr_down, tvb, offset, 5, FALSE);
    offset= offset+5;
}

/*
 * 8.17 RAT Type
 */
static const value_string gtpv2_rat_type_vals[] = {
    {0, "Reserved"},
    {1, "UTRAN"},
    {2, "GERAN"},
    {3, "WLAN"},
    {4, "GAN"},
    {5, "HSPA Evolution"},
    {6, "EUTRAN"},
    {0, NULL}
};

static void
dissect_gtpv2_rat_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    proto_tree_add_item(tree, hf_gtpv2_rat_type, tvb, 0, 1, FALSE);
}

/*
 * 8.18 Serving Network
 */
static void
dissect_gtpv2_serv_net(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    dissect_e212_mcc_mnc(tvb, pinfo, tree, 0, TRUE);
}

/*
 * 8.19 EPS Bearer Level Traffic Flow Template (Bearer TFT)
 */

static void
dissect_gtpv2_bearer_tft(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
	/* The detailed coding of Traffic Aggregate
	 * Description is specified in 3GPP TS 24.008 [5] ,
	 * clause 10.5.6.12, beginning with octet 3..
	 * Use the decoding in packet-gsm_a_gm.c
	 */
	de_sm_tflow_temp(tvb, tree, 0, length, NULL, 0);

}
 /* 8.20 Traffic Aggregate Description (TAD)
 */
static void
dissect_gtpv2_tad(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
	/* The detailed coding of Traffic Aggregate
	 * Description is specified in 3GPP TS 24.008 [5] ,
	 * clause 10.5.6.12, beginning with octet 3..
	 * Use the decoding in packet-gsm_a_gm.c
	 */
	de_sm_tflow_temp(tvb, tree, 0, length, NULL, 0);
}

/*
 * 8.21 User Location Info (ULI)
 *
 * The flags ECGI, TAI, RAI, SAI and CGI in octed 5 indicate if the corresponding
 * fields are present in the IE or not. If one of these flags is set to "0",
 * the corresponding field is not present at all. The respective identities are defined in 3GPP
 * TS 23.003 [2].
 * Editor's Note: The definition of ECGI is missing in 3GPP TS 23.003 v8.1.0.
 * It can be found in 3GPP TS 36.413 v8.3.0, but it is expected that it will be moved
 * to 23.003 in a future version.
 */

static void
decode_gtpv2_uli(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 instance _U_, guint flags)
{
    int offset = 1;

    /* 8.22.1 CGI field  */
    if (flags & GTPv2_ULI_CGI_MASK)
    {
        dissect_e212_mcc_mnc(tvb, pinfo, tree, offset, TRUE);
        offset+=3;
        proto_tree_add_item(tree, hf_gtpv2_uli_cgi_lac, tvb, offset, 2, FALSE);
        proto_tree_add_item(tree, hf_gtpv2_uli_cgi_ci, tvb, offset, 2, FALSE);
        offset+=4;
        if(offset==length)
            return;
    }

    /* 8.22.2 SAI field  */
    if (flags & GTPv2_ULI_SAI_MASK)
    {
        dissect_e212_mcc_mnc(tvb, pinfo, tree, offset, TRUE);
        offset+=3;
        proto_tree_add_item(tree, hf_gtpv2_uli_sai_lac, tvb, offset, 2, FALSE);
        proto_tree_add_item(tree, hf_gtpv2_uli_sai_sac, tvb, offset, 2, FALSE);
        offset+=4;
        if(offset==length)
            return;
    }
    /* 8.22.3 RAI field  */
    if (flags & GTPv2_ULI_RAI_MASK)
    {
        dissect_e212_mcc_mnc(tvb, pinfo, tree, offset, TRUE);
        offset+=3;
        proto_tree_add_item(tree, hf_gtpv2_uli_rai_lac, tvb, offset, 2, FALSE);
        proto_tree_add_item(tree, hf_gtpv2_uli_rai_rac, tvb, offset, 2, FALSE);
        offset+=4;
        if(offset==length)
            return;
    }
    /* 8.22.4 TAI field  */
    if (flags & GTPv2_ULI_TAI_MASK)
    {
        dissect_e212_mcc_mnc(tvb, pinfo, tree, offset, TRUE);
        offset+=3;
        proto_tree_add_item(tree, hf_gtpv2_uli_tai_tac, tvb, offset, 2, FALSE);
        offset+=2;
        if(offset==length)
            return;
    }
    /* 8.22.5 ECGI field */
    if (flags & GTPv2_ULI_ECGI_MASK)
    {
        guint8 octet;
        guint32 octet4;
        guint8 spare;
        guint32 ECGI;
        dissect_e212_mcc_mnc(tvb, pinfo, tree, offset, TRUE);
        offset+=3;
        /* The bits 8 through 5, of octet e+3 (Fig 8.21.5-1 in TS 29.274 V8.2.0) are spare
         * and hence they would not make any difference to the hex string following it, 
		 * thus we directly read 4 bytes from the tvb
		 */

        octet = tvb_get_guint8(tvb,offset);
        spare = octet & 0xF0;
        octet4 = tvb_get_ntohl(tvb,offset);
        ECGI = octet4 & 0x0FFFFFFF;
        proto_tree_add_uint(tree, hf_gtpv2_uli_ecgi_eci_spare, tvb, offset, 1, spare);
        proto_tree_add_uint(tree, hf_gtpv2_uli_ecgi_eci, tvb, offset, 4, ECGI);
        /*proto_tree_add_item(tree, hf_gtpv2_uli_ecgi_eci, tvb, offset, 4, FALSE);*/
        offset+=4;
        if(offset==length)
            return;

    }
}

static void
dissect_gtpv2_uli(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    int offset = 0;
    guint flags;
    flags = tvb_get_guint8(tvb,offset)&0x1f;
    /* ECGI B5 */
    proto_tree_add_item(tree, hf_gtpv2_uli_ecgi_flg, tvb, offset, 1, FALSE);
    /* TAI B4  */
    proto_tree_add_item(tree, hf_gtpv2_uli_tai_flg, tvb, offset, 1, FALSE);
    /* RAI B3  */
    proto_tree_add_item(tree, hf_gtpv2_uli_rai_flg, tvb, offset, 1, FALSE);
    /* SAI B2  */
    proto_tree_add_item(tree, hf_gtpv2_uli_sai_flg, tvb, offset, 1, FALSE);
    /* CGI B1  */
    proto_tree_add_item(tree, hf_gtpv2_uli_cgi_flg, tvb, offset, 1, FALSE);

    decode_gtpv2_uli(tvb, pinfo, tree, item, length, instance, flags);

    return;
}

/* Diameter 3GPP AVP Code: 22 3GPP-User-Location-Info */
/*
 * TS 29.061 v9.2.0
 * 16.4.7.2 Coding 3GPP Vendor-Specific RADIUS attributes
 *
 * For P-GW, the Geographic Location Type values and coding are defined as follows:
 *
 * 0			CGI
 * 1			SAI
 * 2			RAI
 * 3-127		Spare for future use
 * 128		TAI
 * 129		ECGI
 * 130		TAI and ECGI
 * 131-255	Spare for future use
 */

static int
dissect_diameter_3gpp_uli(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_)
{
    int offset = 0;
    guint length;
    guint flags;
    guint flags_3gpp;
    length = tvb_length(tvb);
    flags_3gpp = tvb_get_guint8(tvb,offset);

    switch(flags_3gpp)
    {
    case 128:
        /* TAI */
        flags = GTPv2_ULI_TAI_MASK;
        break;
    case 129:
        /* ECGI */
        flags = GTPv2_ULI_ECGI_MASK;
        break;
    case 130:
        /* TAI and ECGI */
        flags = GTPv2_ULI_TAI_MASK + GTPv2_ULI_ECGI_MASK;
        break;
    default:
        flags = flags_3gpp;
        break;
    }

    decode_gtpv2_uli(tvb, pinfo, tree, NULL, length, 0, flags);
    return length;
}

/*
 * 8.22 Fully Qualified TEID (F-TEID)
 */
static const value_string gtpv2_f_teid_interface_type_vals[] = {
    {0, "S1-U eNodeB GTP-U interface"},
    {1, "S1-U SGW GTP-U interface"},
    {2, "S12 RNC GTP-U interface"},
    {3, "S12 SGW GTP-U interface"},
    {4, "S5/S8 SGW GTP-U interface"},
    {5, "S5/S8 PGW GTP-U interface"},
    {6, "S5/S8 SGW GTP-C interface"},
    {7, "S5/S8 PGW GTP-C interface"},
    {8, "S5/S8 SGW PMIPv6 interface (the 32 bit GRE key is encoded in 32 bit TEID field "
        "and since alternate CoA is not used the control plane and user plane addresses are the same for PMIPv6)"},
    {9, "S5/S8 PGW PMIPv6 interface (the 32 bit GRE key is encoded in 32 bit TEID field "
        "and the control plane and user plane addresses are the same for PMIPv6)"},
    {10, "S11 MME GTP-C interface"},
    {11, "S11/S4 SGW GTP-C interface"},
    {12, "S10 MME GTP-C interface"},
    {13, "S3 MME GTP-C interface"},
    {14, "S3 SGSN GTP-C interface"},
    {15, "S4 SGSN GTP-U interface"},
    {16, "S4 SGW GTP-U interface"},
    {17, "S4 SGSN GTP-C interface"},
    {18, "S16 SGSN GTP-C interface"},
    {19, "eNodeB GTP-U interface for DL data forwarding"},
    {20, "eNodeB GTP-U interface for UL data forwarding"},
    {21, "RNC GTP-U interface for data forwarding"},
    {22, "SGSN GTP-U interface for data forwarding"},
    {23, "SGW GTP-U interface for data forwarding"},
    {24, "Sm MBMS GW GTP-C interface"},
    {25, "Sn MBMS GW GTP-C interface"},
    {26, "Sm MME GTP-C interface"},
    {27, "Sn SGSN GTP-C interface"},
    {28, "SGW GTP-U interface for UL data forwarding"},
    {29, "Sn SGSN GTP-U interface"},
    {0, NULL}
};
static void
dissect_gtpv2_f_teid(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    int offset = 0;
    guint8 v4, v6;

    v4 = tvb_get_guint8(tvb,offset)& 0x80;
    v6 = tvb_get_guint8(tvb,offset)& 0x40;
    proto_tree_add_item(tree, hf_gtpv2_f_teid_v4, tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_gtpv2_f_teid_v6, tvb, offset, 1, FALSE);
    proto_tree_add_item(tree, hf_gtpv2_f_teid_interface_type, tvb, offset, 1, FALSE);

    offset++;
    proto_tree_add_item(tree, hf_gtpv2_f_teid_gre_key, tvb, offset, 4, FALSE);

    offset= offset+4;
    if (v4)
    {
        proto_tree_add_item(tree, hf_gtpv2_f_teid_ipv4, tvb, offset, 4, FALSE);
        offset= offset+4;
    }
    if (v6)
    {
        proto_tree_add_item(tree, hf_gtpv2_f_teid_ipv6, tvb, offset, 16, FALSE);
        offset= offset+16;
    }
}
/*
 * 8.23 TMSI
 */
/*
 * 8.24 Global CN-Id
 */

static void
dissect_gtpv2_g_cn_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
	int		offset = 0;

	dissect_e212_mcc_mnc(tvb, pinfo, tree, 0, TRUE);
	offset +=3;

	proto_tree_add_text(tree, tvb, offset, 2, "CN-Id: %s",
		tvb_bytes_to_str(tvb, offset, 2));
}
/*
 * 8.25 S103 PDN Data Forwarding Info (S103PDF)
 */
static void
dissect_gtpv2_s103pdf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    int offset = 0;

	proto_tree_add_item(tree, hf_gtpv2_hsgw_addr_f_len, tvb, offset, 1, FALSE);
	offset++;

    proto_tree_add_text(tree, tvb, offset, length-offset, "IE data not fully dissected yet");

}
/*
 * 8.26 S1-U Data Forwarding (S1UDF)
 */
/*
 * 8.27 Delay Value
 */

static void
dissect_gtpv2_delay_value(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_,  guint8 instance _U_)
{

    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_delay_value, tvb, offset, 1, FALSE);


}
/*
 * 8.28 Bearer Context (grouped IE)
 */

static void
dissect_gtpv2_bearer_ctx(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_, guint8 instance _U_)
{
    int offset= 0;
    proto_tree *grouped_tree;

    proto_item_append_text(item, "[Grouped IE]");
    grouped_tree = proto_item_add_subtree(item, ett_gtpv2_bearer_ctx);
    dissect_gtpv2_ie_common(tvb, pinfo, grouped_tree, offset, message_type);

}
/* 8.29 Charging ID */
static void
dissect_gtpv2_charging_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_,  guint8 instance _U_)
{

    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_charging_id, tvb, offset, length, FALSE);


}


 /* 8.30 Charging Characteristics
  * The charging characteristics information element is defined in 3GPP TS 32.251 [8]
  * and is a way of informing both the SGW and PGW of the rules for producing charging
  * information based on operator configured triggers. For the encoding of this
  * information element see 3GPP TS 32.298 [9].
  */

static void
dissect_gtpv2_char_char(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{

    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_charging_characteristic, tvb, offset, 2, FALSE);
    if(length>2){
        offset+=2;
        /* These octet(s) is/are present only if explicitly specified */
        proto_tree_add_text(tree, tvb, offset, length-2, "Remaining octets");
    }

}
/* 8.30 Bearer Flag  */
static void
dissect_gtpv2_bearer_flag(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{

    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_bearer_flag, tvb, offset, length, FALSE);


}
/* 8.34 PDN Type  */
static void
dissect_gtpv2_pdn_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{

    int offset = 0;

    if (length != 1) {
        proto_item *expert_item;
        expert_item = proto_tree_add_text(tree, tvb, 0, length, "Wrong length indicated. Expected 1, got %u", length);
        expert_add_info_format(pinfo, expert_item, PI_MALFORMED, PI_ERROR, "Wrong length indicated. Expected 1, got %u", length);
        PROTO_ITEM_SET_GENERATED(expert_item);
        return;
    }

    proto_tree_add_item(tree, hf_gtpv2_pdn_type, tvb, offset, length, FALSE);


}

/* 8.31 Trace Information
 * 8.33 Paging Cause
 */

/* 8.35 Procedure Transaction ID (PTI) */
static void
dissect_gtpv2_pti(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    proto_tree_add_item(tree, hf_gtpv2_pti, tvb, 0, 1, FALSE);
}
/*
 * 8.36 DRX Parameter
 * 8.37 UE Network Capability
 * 8.38 MM Context
 */
/*
 * 8.39 PDN Connection (grouped IE)
 */
static void
dissect_gtpv2_PDN_conn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    int offset= 0;
    proto_tree *grouped_tree;

    proto_item_append_text(item, "[Grouped IE]");
    grouped_tree = proto_item_add_subtree(item, ett_gtpv2_PDN_conn);
    dissect_gtpv2_ie_common(tvb, pinfo, grouped_tree, offset, message_type);
}
/*
 * 8.40 PDU Numbers
 * 8.41 Packet TMSI (P-TMSI)
 * 8.42 P-TMSI Signature
 * 8.43 Hop Counter
 */

/* 8.44 UE Time Zone */

static const value_string gtpv2_ue_time_zone_dst_vals[] = {
    {0, "No Adjustments for Daylight Saving Time"},
    {1, "+1 Hour Adjustments for Daylight Saving Time"},
    {2, "+2 Hour Adjustments for Daylight Saving Time"},
    {3, "Spare"},
    {0, NULL}
};
static void
dissect_gtpv2_ue_time_zone(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_gtpv2_ue_time_zone, tvb, offset, 1, FALSE);

    offset= offset+ 1;
    proto_tree_add_item(tree, hf_gtpv2_ue_time_zone_dst, tvb, offset, 1, FALSE);


}
/*
 * 8.45 Trace Reference
 */
/*
 * 8.46 Complete Request Message
 */
static const value_string gtpv2_complete_req_msg_type_vals[] = {
	{0, "Complete Attach Request Message" 	},
	{1, "Complete TAU Request Message"			},
	{0, NULL																}
};
static void
dissect_complete_request_msg(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
	tvbuff_t  *new_tvb;
	int        offset;

	offset = 0;

	proto_tree_add_item(tree, hf_gtpv2_complete_req_msg_type, tvb, offset, 1, FALSE);

	offset++;

	/* Add the Complete Request Message */
	new_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(nas_eps_handle, new_tvb, pinfo, tree);

}

/*
 * 8.47 GUTI
 */
static void
dissect_gtpv2_guti(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    int offset = 0;

	offset = 0;
	
	dissect_e212_mcc_mnc(tvb, pinfo, tree, 0, TRUE);
	offset += 3;

	proto_tree_add_item(tree, hf_gtpv2_mme_grp_id, tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_gtpv2_mme_code, tvb, offset, 1, FALSE);
	offset++;

	proto_tree_add_item(tree, hf_gtpv2_m_tmsi, tvb, offset, -1, FALSE);
}

/*
 * 8.48 Fully Qualified Container (F-Container)
 */

static const value_string gtpv2_container_type_vals[] = {
    {1, "UTRAN transparent container"},
    {2, "BSS container"},
    {3, "E-UTRAN transparent container"},
    {0, NULL}
};


static void
dissect_gtpv2_F_container(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length,guint8 message_type,  guint8 instance _U_)
{
	tvbuff_t *tvb_new;
    int offset = 0;
	guint8 container_type;

	/* Octets	8	7	6	5	4	3	2	1
	 * 5			Spare	  |	Container Type
	 */
    proto_tree_add_item(tree, hf_gtpv2_container_type, tvb, offset, 1, FALSE);
	container_type = tvb_get_guint8(tvb,offset);
	offset++;
	if(message_type == GTPV2_FORWARD_CTX_NOTIFICATION){
		switch(container_type){
			case 3:
				/* E-UTRAN transparent container */
				tvb_new = tvb_new_subset_remaining(tvb, offset);
				dissect_s1ap_ENB_StatusTransfer_TransparentContainer_PDU(tvb_new, pinfo, tree);
				return;
			default:
				break;
		}
	}
	proto_tree_add_text(tree, tvb, offset, length-offset, "Not dissected yet");

}

/*
 * 8.49 Fully Qualified Cause (F-Cause)
 */

static const value_string gtpv2_cause_type_vals[] = {
    {0,  "Radio Network Layer"},
    {1,  "Transport Layer"},
    {2,  "NAS"},
    {3,  "Protocol"},
    {4,  "Miscellaneous"},
    {5,  "<spare>"},
    {6,  "<spare>"},
    {7,  "<spare>"},
    {8,  "<spare>"},
    {9,  "<spare>"},
    {10, "<spare>"},
    {11, "<spare>"},
    {12, "<spare>"},
    {13, "<spare>"},
    {14, "<spare>"},
    {15, "<spare>"},
    {0, NULL}
};
static value_string_ext gtpv2_cause_type_vals_ext = VALUE_STRING_EXT_INIT(gtpv2_cause_type_vals);

static void
dissect_gtpv2_F_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{

    int offset = 0;
	guint8 cause_type;

	/* The value of Instance field of the F-Cause IE in a GTPv2 message shall indicate 
	 * whether the F-Cause field contains RANAP Cause, BSSGP Cause or RAN Cause. 
	 * If the F-Cause field contains RAN Cause, the Cause Type field shall contain 
	 * the RAN cause subcategory as specified in 3GPP TS 36.413 [10] and it shall be
	 * encoded as in Table 8.49-1. 
	 * If the F-Cause field contains BSSGP Cause or RANAP Cause, 
	 * the Cause Type field shall be ignored by the receiver.
	 */
	if(message_type == GTPV2_FORWARD_RELOCATION_REQ){
		switch(instance){
			case 0:
				proto_item_append_text(item, "[RAN Cause]");
				proto_tree_add_item(tree, hf_gtpv2_cause_type, tvb, offset, 1, FALSE);
				cause_type = tvb_get_guint8(tvb,offset);
				offset++;
				switch(cause_type){
					case 0:
						/* CauseRadioNetwork */
						proto_tree_add_item(tree, hf_gtpv2_CauseRadioNetwork, tvb, offset, 1, FALSE);
						break;
					case 1:
						/* CauseTransport */
						proto_tree_add_item(tree, hf_gtpv2_CauseTransport, tvb, offset, 1, FALSE);
						break;
					case 2:
						/* CauseNas */
						proto_tree_add_item(tree, hf_gtpv2_CauseNas, tvb, offset, 1, FALSE);
						break;
					case 3:
						/* CauseProtocol */
						proto_tree_add_item(tree, hf_gtpv2_CauseProtocol, tvb, offset, 1, FALSE);
						break;
					case 4:
						/* CauseMisc */
						proto_tree_add_item(tree, hf_gtpv2_CauseMisc, tvb, offset, 1, FALSE);
						break;
					default:
						break;
				}
				return;
				break;
			case 1:
				proto_item_append_text(item, "[RANAP Cause]");
				break;
			case 2:
				proto_item_append_text(item, "[BSSGP Cause]");
				break;
			default:
				break;
		}
	}
	proto_tree_add_text(tree, tvb, offset, length-offset, "Not dissected yet");

}
/*
 * 8.50 Selected PLMN ID
 */
/*
 * 8.51 Target Identification
 */

static const value_string gtpv2_target_type_vals[] = {
    {0,  "RNC ID"},
    {1,  "Macro eNodeB ID"},
    {2,  "Cell Identifier"},
    {3,  "Home eNodeB ID"},
    {0, NULL}
};
static value_string_ext gtpv2_target_type_vals_ext = VALUE_STRING_EXT_INIT(gtpv2_target_type_vals);

static void
dissect_gtpv2_target_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
	tvbuff_t *tvb_new;
    int offset = 0;
	guint8 target_type;

	proto_tree_add_item(tree, hf_gtpv2_target_type, tvb, 0, 1, FALSE);
	target_type = tvb_get_guint8(tvb,offset);
	offset++;
	switch(target_type){
		case 0:
			/* RNC ID
			 * In this case the Target ID field shall be encoded as the Target
			 * RNC-ID part of the "Target ID" parameter in 3GPP TS 25.413 [33]. Therefore, the "Choice Target ID" that indicates
			 * "Target RNC-ID" (numerical value of 0x20) shall not be included (value in octet 5 specifies the target type).
			 */
			tvb_new = tvb_new_subset_remaining(tvb, offset);
			dissect_ranap_TargetRNC_ID_PDU(tvb_new, pinfo, tree);
			return;
			break;
		case 1:
			/* Macro eNodeB ID*/
			tvb_new = tvb_new_subset_remaining(tvb, offset);
			dissect_e212_mcc_mnc(tvb_new, pinfo, tree, 0, TRUE);
			offset+=3;
			/* The Macro eNodeB ID consists of 20 bits. 
			 * Bit 4 of Octet 4 is the most significant bit and bit 1 of Octet 6 is the least significant bit.
			 */
			proto_tree_add_item(tree, hf_gtpv2_macro_enodeb_id, tvb, offset, 3, FALSE);
			offset+=3;
			/* Tracking Area Code (TAC) */
			proto_tree_add_item(tree, hf_gtpv2_uli_tai_tac, tvb, offset, 2, FALSE);
			return;

		case 2:
			/* Cell Identifier */
			/* Target ID field shall be same as the Octets 3 to 10 of the Cell Identifier IEI
			* in 3GPP TS 48.018 [34].
			*/
		case 3:
			/* Home eNodeB ID */
			/* Octet 10 to 12 Home eNodeB ID */
			/* Octet 13 to 14 Tracking Area Code (TAC) */

		default:
			break;
	}
	proto_tree_add_text(tree, tvb, offset, length-offset, "Not dissected yet");

}

/*
 * 8.52 Void
 * 8.53 Packet Flow ID
 * 8.54 RAB Context
 * 8.55 Source RNC PDCP context info
 * 8.56 UDP Source Port Number
 */

/*8.57 APN Restriction */
static void
dissect_gtpv2_apn_rest(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    proto_tree_add_item(tree, hf_gtpv2_apn_rest, tvb, 0, 1, FALSE);
}

/* 8.58 Selection Mode */
static const value_string gtpv2_selec_mode_vals[] = {
    {0, "MS or network provided APN, subscribed verified"},
    {1, "MS provided APN, subscription not verified"},
    {2, "Network provided APN, subscription not verified"},
    {3, "Network provided APN, subscription not verified (Basically for Future use"},
    {0, NULL}
};

static void
dissect_gtpv2_selec_mode(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    int offset=0;

    proto_tree_add_item(tree, hf_gtpv2_selec_mode, tvb, offset, 1, FALSE);
}


 /* 8.59 Source Identification */

 /* 8.60 Bearer Control Mode */
 static const value_string gtpv2_bearer_control_mode_vals[] = {
    {0, "Selected Bearer Control Mode-'MS_only'"},
    {1, "Selected Bearer Control Mode-'Network_only'"},
    {2, "Selected Bearer Control Mode-'MS/NW'"},
    {0, NULL}
};

static void
dissect_gtpv2_bearer_control_mode(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
    proto_tree_add_item(tree, hf_gtpv2_bearer_control_mode, tvb, 0, 1, FALSE);
}
/*
 * 8.61 Change Reporting Action
 */
static const value_string gtpv2_cng_rep_act_vals[] = {
    {0, "Stop Reporting"},
    {1, "Start Reporting CGI/SAI"},
    {2, "Start Reporting RAI"},
    {0, NULL}
};

static void
dissect_gtpv2_cng_rep_act(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{

    proto_tree_add_item(tree, hf_gtpv2_cng_rep_act, tvb, 0, 1, FALSE);
}
/*
 * 8.62 Fully qualified PDN Connection Set Identifier (FQ-CSID)
 * 8.63 Channel needed
 * 8.64 eMLPP Priority
 */

/*8.65 Node Type */
static const value_string gtpv2_node_type_vals[] = {
    {0, "MME"},
    {1, "SGSN"},
    {0, NULL}
};

static void
dissect_gtpv2_node_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{

    proto_tree_add_item(tree, hf_gtpv2_node_type, tvb, 0, 1, FALSE);
}

 /* 
  * 8.66 Fully Qualified Domain Name (FQDN)
  */
static void
dissect_gtpv2_fqdn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
	/* The FQDN field encoding shall be identical to the encoding of
	 * a FQDN within a DNS message of section 3.1 of IETF
	 * RFC 1035 [31] but excluding the trailing zero byte.
	 */

    proto_tree_add_text(tree, tvb, 0, length, "Not dissected yet");
}
/*
 * 8.67 Private Extension
 */
static void
dissect_gtpv2_private_ext(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_,guint8 message_type _U_,  guint8 instance _U_)
{
	int offset = 0;

	/* oct 5 -7 Enterprise ID */
    proto_tree_add_item(tree, hf_gtpv2_enterprise_id, tvb, offset, 2, FALSE);
	offset+=2;
	proto_tree_add_text(tree, tvb, offset, length-2, "Proprietary value");

}
/*
 * 8.68	Transaction Identifier (TI)
 */
static void
dissect_gtpv2_ti(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, guint8 instance _U_)
{

/* 5 to (n+4)	Transaction Identifier */
	    proto_tree_add_item(tree, hf_gtpv2_ti, tvb, 0, length, FALSE);

}

typedef struct _gtpv2_ie {
    int ie_type;
    void (*decode) (tvbuff_t *, packet_info *, proto_tree *, proto_item *, guint16, guint8, guint8);
} gtpv2_ie_t;

static const gtpv2_ie_t gtpv2_ies[] = {
    {GTPV2_IE_IMSI, dissect_gtpv2_imsi},
    {GTPV2_IE_CAUSE, dissect_gtpv2_cause},                         /* 2, Cause (without embedded offending IE) 8.4 */
    {GTPV2_REC_REST_CNT, dissect_gtpv2_recovery},                  /* 3, Recovery (Restart Counter) 8.5 */
                                                                   /* 4-50 Reserved for S101 interface Extendable / See 3GPP TS 29.276 [14] */
                                                                   /* 51-70 Reserved for Sv interface Extendable / See 3GPP TS 29.280 [15] */
    {GTPV2_APN, dissect_gtpv2_apn},                                /* 71, Access Point Name (APN) 8.6 */
    {GTPV2_AMBR, dissect_gtpv2_ambr},                              /* 72, Aggregate Maximum Bit Rate (AMBR) */
    {GTPV2_EBI, dissect_gtpv2_ebi},                                /* 73, EPS Bearer ID (EBI)  8.8 */
    {GTPV2_IP_ADDRESS, dissect_gtpv2_ip_address},                  /* 74, IP Address */
    {GTPV2_MEI, dissect_gtpv2_mei},                                /* 74, Mobile Equipment Identity */
    {GTPV2_IE_MSISDN, dissect_gtpv2_msisdn},                       /* 76, MSISDN 8.11 */
    {GTPV2_INDICATION, dissect_gtpv2_ind},                         /* 77 Indication 8.12 */
    {GTPV2_PCO, dissect_gtpv2_pco},                                /* 78 Protocol Configuration Options (PCO) 8.13 */
    {GTPV2_PAA, dissect_gtpv2_paa},                                /* 79 PDN Address Allocation (PAA) 8.14 */
    {GTPV2_BEARER_QOS,dissect_gtpv2_bearer_qos},                   /* 80 Bearer Level Quality of Service (Bearer QoS) 8.15 */
    {GTPV2_IE_FLOW_QOS, dissect_gtpv2_flow_qos},                   /* 81 Flow Quality of Service (Flow QoS) 8.16 */
    {GTPV2_IE_RAT_TYPE, dissect_gtpv2_rat_type},                   /* 82, RAT Type  8.17 */
    {GTPV2_IE_SERV_NET, dissect_gtpv2_serv_net},                   /* 83, Serving Network 8.18 */
    {GTPV2_BEARER_TFT, dissect_gtpv2_bearer_tft},                  /* 84, Bearer TFT 8.19 */
    {GTPV2_IE_TAD, dissect_gtpv2_tad},                             /* 85, Traffic Aggregate Description 8.20 */
    {GTPV2_IE_ULI, dissect_gtpv2_uli},                             /* 86, User Location Info (ULI) 8.22 */
    {GTPV2_IE_F_TEID, dissect_gtpv2_f_teid},                       /* 87, Fully Qualified Tunnel Endpoint Identifier (F-TEID) 8.23 */
    {GTPV2_IE_GLOBAL_CNID, dissect_gtpv2_g_cn_id},                 /* 89, Global CN-Id 8.25 */
    {GTPV2_IE_S103PDF, dissect_gtpv2_s103pdf},                     /* 90, S103 PDN Data Forwarding Info (S103PDF) 8.25 */
    {GTPV2_IE_DEL_VAL, dissect_gtpv2_delay_value},                 /* 92, Delay Value 8.29 */
    {GTPV2_IE_BEARER_CTX,dissect_gtpv2_bearer_ctx},                /* 93, Bearer Context  8.31 */
    {GTPV2_IE_CHAR_ID, dissect_gtpv2_charging_id},                 /* 94, Charging Id */
    {GTPV2_IE_CHAR_CHAR, dissect_gtpv2_char_char},                 /* 95 Charging Characteristic */
     
    {GTPV2_BEARER_FLAG, dissect_gtpv2_bearer_flag},                /* 97, Bearer Flag */
    {GTPV2_IE_PDN_TYPE, dissect_gtpv2_pdn_type},                   /* 99, PDN Type */
    {GTPV2_IE_PTI, dissect_gtpv2_pti},                             /* 100, Procedure Transaction Id */
	{GTPV2_PDN_CONN, dissect_gtpv2_PDN_conn},			           /* 109, PDN Connection */                         
    {GTPV2_IE_UE_TIME_ZONE, dissect_gtpv2_ue_time_zone},           /* 114, UE Time Zone */
    {GTPV2_IE_COMPLETE_REQUEST_MSG, dissect_complete_request_msg}, /* 116, Complete Request message 8.46 */

    {GTPV2_IE_GUTI, dissect_gtpv2_guti},                           /* 117, GUTI 8.47 */
	{GTPV2_IE_F_CONTAINER, dissect_gtpv2_F_container},		       /* 118, Fully Qualified Container (F-Container) */
	{GTPV2_IE_F_CAUSE, dissect_gtpv2_F_cause},				       /* 119, Fully Qualified Cause (F-Cause) */
	{GTPV2_TARGET_ID, dissect_gtpv2_target_id},			           /* 121, Target Identification */
    {GTPV2_APN_RESTRICTION, dissect_gtpv2_apn_rest},               /* 127, APN Restriction */
    
    {GTPV2_SELEC_MODE,dissect_gtpv2_selec_mode},					/* 128 Selection Mode */
    {GTPV2_BEARER_CONTROL_MODE,dissect_gtpv2_bearer_control_mode},	/* 130 Bearer Control Mode*/
    {GTPV2_CNG_REP_ACT ,dissect_gtpv2_cng_rep_act},					/* 131 Change Reporting Action 8.61 */
    {GTPV2_NODE_TYPE ,dissect_gtpv2_node_type},						/* 135 Node Type 8.65 */
	{GTPV2_FQDN, dissect_gtpv2_fqdn},								/* 136 8.66 Fully Qualified Domain Name (FQDN) */
	{GTPV2_TI, dissect_gtpv2_ti},									/* 137 8.68	Transaction Identifier (TI) */
																	/* 137-254 Spare. For future use. FFS */
	{GTPV2_PRIVATE_EXT,dissect_gtpv2_private_ext},


    {0, dissect_gtpv2_unknown}
};



static void
dissect_gtpv2_ie_common(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree, gint offset, guint8 message_type)
{
    proto_tree *ie_tree;
    proto_item *ti;
    tvbuff_t *ie_tvb;
    guint8 type, instance;
    guint16 length;
    int i;
    /*
     * Octets   8   7   6   5       4   3   2   1
     *  1       Type
     *  2-3     Length = n
     *  4       CR          Spare   Instance
     * 5-(n+4)  IE specific data
     */
    while(offset < (gint)tvb_reported_length(tvb)){
        /* Get the type and length */
        type = tvb_get_guint8(tvb,offset);
        length = tvb_get_ntohs(tvb, offset+1);
        ti = proto_tree_add_text(tree, tvb, offset, 4 + length, "%s : ", val_to_str(type, gtpv2_element_type_vals, "Unknown"));
        ie_tree = proto_item_add_subtree(ti, ett_gtpv2_ie);
        /* Octet 1 */
        proto_tree_add_item(ie_tree, hf_gtpv2_ie, tvb, offset, 1, FALSE);
        offset++;

        /*Octet 2 - 3 */
        proto_tree_add_item(ie_tree, hf_gtpv2_ie_len, tvb, offset, 2, FALSE);
        offset+=2;
        /* CR Spare Instance Octet 4*/
        proto_tree_add_item(ie_tree, hf_gtpv2_cr, tvb, offset, 1, FALSE);

        instance = tvb_get_guint8(tvb,offset)& 0x0f;
        proto_tree_add_item(ie_tree, hf_gtpv2_instance, tvb, offset, 1, FALSE);
        offset++;

        /* TODO: call IE dissector here */
        if(type==GTPV2_IE_RESERVED){
            /* Treat IE type zero specal as type zero is used to end the loop in the else branch */
            proto_tree_add_text(ie_tree, tvb, offset, length, "IE type Zero is Reserved and should not be used");
        }else{
            i = -1;
            /* Loop over the IE dissector list to se if we find an entry, the last entry will have ie_type=0 breaking the loop */
            while (gtpv2_ies[++i].ie_type){
                if (gtpv2_ies[i].ie_type == type)
                    break;
            }
            /* Just give the IE dissector the IE */
            ie_tvb = tvb_new_subset_remaining(tvb, offset);
            (*gtpv2_ies[i].decode) (ie_tvb, pinfo , ie_tree, ti, length, message_type, instance);
        }

        offset = offset + length;
    }
}

static void
dissect_gtpv2(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
    proto_tree *gtpv2_tree, *flags_tree;
    proto_item *ti, *tf;
    guint8 message_type, t_flag;
    int offset = 0;


    /* Currently we get called from the GTP dissector no need to check the version */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GTPv2");
    col_clear(pinfo->cinfo, COL_INFO);

    /* message type is in octet 2 */
    message_type = tvb_get_guint8(tvb,1);
    if (check_col(pinfo->cinfo, COL_INFO))
        col_add_str(pinfo->cinfo, COL_INFO, val_to_str(message_type, gtpv2_message_type_vals, "Unknown"));


    proto_tree_add_item(tree, proto_gtpv2, tvb, offset, -1, FALSE);

    if (tree) {
        ti = proto_tree_add_text(tree, tvb, offset, -1, "%s", val_to_str(message_type, gtpv2_message_type_vals, "Unknown"));
        gtpv2_tree = proto_item_add_subtree(ti, ett_gtpv2);

        /* Control Plane GTP uses a variable length header. Control Plane GTP header
         * length shall be a multiple of 4 octets.
         * Figure 5.1-1 illustrates the format of the GTPv2-C Header.
         * Bits       8  7  6   5       4   3       2       1
         * Octets   1 Version   P       T   Spare   Spare   Spare
         *          2 Message Type
         *          3 Message Length (1st Octet)
         *          4 Message Length (2nd Octet)
         *  m-k(m+3)    If T flag is set to 1, then TEID shall be placed into octets 5-8.
         *              Otherwise, TEID field is not present at all.
         *  n-(n+2)   Sequence Number
         * (n+3)      Spare
         * Figure 5.1-1: General format of GTPv2 Header for Control Plane
         */
        tf = proto_tree_add_item(gtpv2_tree, hf_gtpv2_flags, tvb, offset, 1, FALSE);
        flags_tree = proto_item_add_subtree(tf, ett_gtpv2_flags);

        /* Octet 1 */
        t_flag = (tvb_get_guint8(tvb,offset) & 0x08)>>3;
        proto_tree_add_item(flags_tree, hf_gtpv2_version, tvb, offset, 1, FALSE);
        proto_tree_add_item(flags_tree, hf_gtpv2_p, tvb, offset, 1, FALSE);
        proto_tree_add_item(flags_tree, hf_gtpv2_t, tvb, offset, 1, FALSE);
        offset++;

        /* Octet 2 */
        proto_tree_add_item(gtpv2_tree, hf_gtpv2_message_type, tvb, offset, 1, FALSE);
        offset++;
        /* Octet 3 - 4 */
        proto_tree_add_item(gtpv2_tree, hf_gtpv2_msg_length, tvb, offset, 2, FALSE);
        offset+=2;

        if(t_flag){
            /* Tunnel Endpoint Identifier 4 octets */
            proto_tree_add_item(gtpv2_tree, hf_gtpv2_teid, tvb, offset, 4, FALSE);
            offset+=4;
        }
        /* Sequence Number 3 octets */
        proto_tree_add_item(gtpv2_tree, hf_gtpv2_seq, tvb, offset, 3, FALSE);
        offset+=3;

        /* Spare 1 octet */
        proto_tree_add_item(gtpv2_tree, hf_gtpv2_spare, tvb, offset, 1, FALSE);
        offset+=1;

        dissect_gtpv2_ie_common(tvb, pinfo, gtpv2_tree, offset, message_type);
    }


}
void proto_register_gtpv2(void)
{
    static hf_register_info hf_gtpv2[] = {
        {&hf_gtpv2_flags,
        {"Flags", "gtpv2.flags",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_version,
        {"Version", "gtpv2.version",
        FT_UINT8, BASE_DEC, NULL, 0xe0,
        NULL, HFILL}
        },
        {&hf_gtpv2_p,
        {"P", "gtpv2.p",
        FT_UINT8, BASE_DEC, NULL, 0x10,
        "If Piggybacked message is present or not", HFILL}
        },        
        { &hf_gtpv2_t,
        {"T", "gtpv2.t",
        FT_UINT8, BASE_DEC, NULL, 0x08,
        "If TEID field is present or not", HFILL}
        },
        { &hf_gtpv2_message_type,
        {"Message Type", "gtpv2.message_type",
        FT_UINT8, BASE_DEC, VALS(gtpv2_message_type_vals), 0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_msg_length,
        {"Message Length", "gtpv2.msg_lengt",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_teid,
        {"Tunnel Endpoint Identifier", "gtpv2.teid",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "TEID", HFILL}
        },
        { &hf_gtpv2_seq,
        {"Sequence Number", "gtpv2.seq",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "SEQ", HFILL}
        },
        { &hf_gtpv2_spare,
        {"Spare", "gtpv2.spare",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_ie,
        {"IE Type", "gtpv2.ie_type",
        FT_UINT8, BASE_DEC, VALS(gtpv2_element_type_vals), 0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_ie_len,
        {"IE Length", "gtpv2.ie_len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "length of the information element excluding the first four octets", HFILL}
        },
        { &hf_gtpv2_cr,
        {"CR flag", "gtpv2.cr",
        FT_UINT8, BASE_DEC, NULL, 0xe0,
        NULL, HFILL}
        },
        { &hf_gtpv2_instance,
        {"Instance", "gtpv2.instance",
        FT_UINT8, BASE_DEC, NULL, 0x0f,
        NULL, HFILL}
        },
        {&hf_gtpv2_imsi,
        {"IMSI(International Mobile Subscriber Identity number)", "gtpv2.imsi",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL}
        },
        { &hf_gtpv2_cause,
        {"Cause", "gtpv2.cause",
        FT_UINT8, BASE_DEC, VALS(gtpv2_cause_vals), 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_cause_cs,
        {"Cause Source","gtpv2.cs",
        FT_BOOLEAN, 8, VALS(gtpv2_cause_cs), 0x01,
        NULL, HFILL}
        },
        { &hf_gtpv2_rec,
        {"Restart Counter", "gtpv2.rec",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_apn,
        {"APN (Access Point Name)", "gtpv2.apn",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_ambr_up,
        {"AMBR Uplink (Aggregate Maximum Bit Rate for Uplink)", "gtpv2.ambr_up",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_ambr_down,
        {"AMBR Downlink(Aggregate Maximum Bit Rate for Downlink)", "gtpv2.ambr_down",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_ebi,
        {"EPS Bearer ID (EBI)", "gtpv2.ebi",
        FT_UINT8, BASE_DEC, NULL, 0x0f,
        NULL, HFILL}
        },
        { &hf_gtpv2_ip_address_ipv4,
        {"IP address IPv4", "gtpv2.ip_address_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_ip_address_ipv6,
        {"IP address IPv6", "gtpv2.ip_address_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_mei,
        {"MEI(Mobile Equipment Identity)", "gtpv2.mei",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL}
        },

        {&hf_gtpv2_daf,
        {"DAF (Dual Address Bearer Flag)", "gtpv2.daf",
        FT_BOOLEAN, 8, NULL, 0x80, "DAF", HFILL}
        },
        {&hf_gtpv2_dtf,
        {"DTF (Direct Tunnel Flag)","gtpv2.dtf",
        FT_BOOLEAN, 8, NULL, 0x40, "DTF", HFILL}
        },
        {&hf_gtpv2_hi,
        {"HI (Handover Indication)", "gtpv2.hi",
        FT_BOOLEAN, 8, NULL, 0x20, "HI", HFILL}
        },
        {&hf_gtpv2_dfi,
        {"DFI (Direct Forwarding Indication)", "gtpv2.dfi",
        FT_BOOLEAN, 8, NULL, 0x10, "DFI", HFILL}
        },
        {&hf_gtpv2_oi,
        {"OI (Operation Indication)","gtpv2.oi",
        FT_BOOLEAN, 8, NULL, 0x08, "OI", HFILL}
        },
        {&hf_gtpv2_isrsi,
        {"ISRSI (Idle mode Signalling Reduction Supported Indication)", "gtpv2.isrsi",
        FT_BOOLEAN, 8, NULL, 0x04, "ISRSI", HFILL}
        },
        {&hf_gtpv2_israi,
        {"ISRAI (Idle mode Signalling Reduction Activation Indication)",    "gtpv2.israi",
        FT_BOOLEAN, 8, NULL, 0x02, "ISRAI", HFILL}
        },
        {&hf_gtpv2_sgwci,
        {"SGWCI (SGW Change Indication)", "gtpv2.sgwci",
        FT_BOOLEAN, 8, NULL, 0x01, "SGWCI", HFILL}
        },
        {&hf_gtpv2_pt,
        {"PT (Protocol Type)", "gtpv2.pt",
        FT_BOOLEAN, 8, NULL, 0x08, "PT", HFILL}
        },
        {&hf_gtpv2_tdi,
        {"TDI (Teardown Indication)", "gtpv2.tdi",
        FT_BOOLEAN, 8, NULL, 0x04, "TDI", HFILL}
        },
        {&hf_gtpv2_si,
        {"SI (Scope Indication)", "gtpv2.si",
        FT_BOOLEAN, 8, NULL, 0x02, "SI", HFILL}
        },
        {&hf_gtpv2_msv,
        {"MSV (MS Validated)", "gtpv2.msv",
        FT_BOOLEAN, 8, NULL, 0x01, "MSV", HFILL}
        },
        { &hf_gtpv2_pdn_type,
        {"PDN Type", "gtpv2.pdn_type",
        FT_UINT8, BASE_DEC, VALS(gtpv2_pdn_type_vals), 0x07,
        NULL, HFILL}
        },
        { &hf_gtpv2_pdn_ipv4,
        {"PDN IPv4", "gtpv2.pdn_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_pdn_ipv6_len,
        {"IPv6 Prefix Length", "gtpv2.pdn_ipv6_len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_pdn_ipv6,
        {"PDN IPv6", "gtpv2.pdn_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_pvi,
        {"PVI (Pre-emption Vulnerability)", "gtpv2.bearer_qos_pvi",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_pl,
        {"PL (Priority Level)", "gtpv2.bearer_qos_pl",
        FT_UINT8, BASE_DEC, NULL, 0x3c,
        NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_pci,
        {"PCI (Pre-emption Capability)", "gtpv2.bearer_qos_pci",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_label_qci,
        {"Label (QCI)", "gtpv2.bearer_qos_label_qci",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_mbr_up,
        {"Maximum Bit Rate For Uplink", "gtpv2.bearer_qos_mbr_up",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_mbr_down,
        {"Maximum Bit Rate For Downlink", "gtpv2.bearer_qos_mbr_down",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_gbr_up,
        {"Guaranteed Bit Rate For Uplink", "gtpv2.bearer_qos_gbr_up",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_bearer_qos_gbr_down,
        {"Guaranteed Bit Rate For Downlink", "gtpv2.bearer_qos_gbr_down",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_flow_qos_label_qci,
        {"Label (QCI)", "gtpv2.flow_qos_label_qci",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_flow_qos_mbr_up,
        {"Maximum Bit Rate For Uplink", "gtpv2.flow_qos_mbr_up",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_flow_qos_mbr_down,
        {"Maximum Bit Rate For Downlink", "gtpv2.flow_qos_mbr_down",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_flow_qos_gbr_up,
        {"Guaranteed Bit Rate For Uplink", "gtpv2.flow_qos_gbr_up",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_flow_qos_gbr_down,
        {"Guaranteed Bit Rate For Downlink", "gtpv2.flow_qos_gbr_down",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_rat_type,
        {"RAT Type", "gtpv2.rat_type",
        FT_UINT8, BASE_DEC, VALS(gtpv2_rat_type_vals), 0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_uli_ecgi_flg,
        {"ECGI Present Flag)", "gtpv2.uli_ecgi_flg",
        FT_BOOLEAN, 8, NULL, GTPv2_ULI_ECGI_MASK,
        NULL, HFILL}
        },
        { &hf_gtpv2_uli_tai_flg,
        {"TAI Present Flag)", "gtpv2.uli_tai_flg",
        FT_BOOLEAN, 8, NULL, GTPv2_ULI_TAI_MASK,
        NULL, HFILL}
        },
        { &hf_gtpv2_uli_rai_flg,
        {"RAI Present Flag)", "gtpv2.uli_rai_flg",
        FT_BOOLEAN, 8, NULL, GTPv2_ULI_RAI_MASK,
        NULL, HFILL}
        },
        { &hf_gtpv2_uli_sai_flg,
        {"SAI Present Flag)", "gtpv2.uli_sai_flg",
        FT_BOOLEAN, 8, NULL, GTPv2_ULI_SAI_MASK,
        NULL, HFILL}
        },
        { &hf_gtpv2_uli_cgi_flg,
        {"CGI Present Flag)", "gtpv2.uli_cgi_flg",
        FT_BOOLEAN, 8, NULL, GTPv2_ULI_CGI_MASK,
        NULL, HFILL}
        },
        { &hf_gtpv2_uli_cgi_lac,
        {"Location Area Code", "gtpv2.uli_cgi_lac",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_uli_cgi_ci,
        {"Cell Identity", "gtpv2.uli_cgi_ci",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_uli_sai_lac,
        {"Location Area Code", "gtpv2.uli_sai_lac",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_uli_sai_sac,
        {"Service Area Code", "gtpv2.uli_sai_sac",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_uli_rai_lac,
        {"Location Area Code", "gtpv2.uli_rai_lac",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_uli_rai_rac,
        {"Routing Area Code", "gtpv2.uli_rai_rac",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_uli_tai_tac,
        {"Tracking Area Code", "gtpv2.uli_tai_tac",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_uli_ecgi_eci,
        {"ECI (E-UTRAN Cell Identifier)", "gtpv2.uli_ecgi_eci",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_uli_ecgi_eci_spare,
        {"Spare", "gtpv2.uli_ecgi_eci_spare",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_f_teid_v4,
        {"V4 (True-IPV4 address field Exists,False-Doesn't Exist in F-TEID)", "gtpv2.f_teid_v4",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL}
        },
        {&hf_gtpv2_f_teid_v6,
        {"V6 (True-IPV6 address field Exists,False-Doesn't Exist in F-TEID)", "gtpv2.f_teid_v6",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL}
        },
        {&hf_gtpv2_f_teid_interface_type,
        {"Interface Type", "gtpv2.f_teid_interface_type",
        FT_UINT8, BASE_DEC, VALS(gtpv2_f_teid_interface_type_vals), 0x1f,
        NULL , HFILL}
        },
        {&hf_gtpv2_f_teid_gre_key,
        {"TEID/GRE Key", "gtpv2.f_teid_gre_key",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL , HFILL}
        },
        { &hf_gtpv2_f_teid_ipv4,
        {"F-TEID IPv4", "gtpv2.f_teid_ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_f_teid_ipv6,
        {"F-TEID IPv6", "gtpv2.f_teid_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
        },
		{ &hf_gtpv2_hsgw_addr_f_len,
        {"HSGW Address for forwarding Length", "gtpv2.hsgw_addr_f_len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_delay_value,
        {"Delay Value (In integer multiples of 50 milliseconds or zero)", "gtpv2.delay_value",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_charging_id,
        {"Charging id", "gtpv2.charging_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_charging_characteristic,
        {"Charging Characteristic", "gtpv2.charging_characteristic",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_bearer_flag,
        {"Bearer Flags(PPC(Prohibit Payload Compression) True-SGSN attempts to compress the payload, False-SGSN doesn't attempt to compress the payload)",
        "gtpv2.bearer_flag",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL}
        },
        {&hf_gtpv2_pti,
        {"Procedure Transaction Id", "gtpv2.pti",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_ue_time_zone,
        {"Time Zone","gtpv2.ue_time_zone",
        FT_UINT8, BASE_DEC, NULL,0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_ue_time_zone_dst,
        {"Daylight Saving Time","gtpv2.ue_time_zone_dst",
        FT_UINT8, BASE_DEC, VALS(gtpv2_ue_time_zone_dst_vals),0x03,
        NULL, HFILL}
        },
		{ &hf_gtpv2_complete_req_msg_type,
        {"Complete Request Message Type","gtpv2.complete_req_msg_type",
        FT_UINT8, BASE_DEC, VALS(gtpv2_complete_req_msg_type_vals),0x0,
        NULL, HFILL}
        },
		{&hf_gtpv2_mme_grp_id,
        {"MME Group ID","gtpv2.mme_grp_id",
        FT_UINT16, BASE_DEC, NULL,0x0,
        NULL, HFILL}
        },
		{ &hf_gtpv2_mme_code,
        {"MME Code","gtpv2.mme_code",
        FT_UINT8, BASE_DEC, NULL,0x0,
        NULL, HFILL}
        },
		{ &hf_gtpv2_m_tmsi,
        {"M-TMSI","gtpv2.m_tmsi",
        FT_BYTES, BASE_NONE, NULL,0x0,
        NULL, HFILL}
        },
		{ &hf_gtpv2_container_type,
        {"Container Type","gtpv2.container_type",
        FT_UINT8, BASE_DEC, VALS(gtpv2_container_type_vals),0x0f,
        NULL, HFILL}
        },
		{ &hf_gtpv2_cause_type,
        {"Cause Type","gtpv2.cause_type",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_cause_type_vals_ext,0x0f,
        NULL, HFILL}
        },
		{ &hf_gtpv2_CauseRadioNetwork,
        {"Radio Network Layer Cause","gtpv2.CauseRadioNetwork",
        FT_UINT8, BASE_DEC, VALS(&s1ap_CauseRadioNetwork_vals),0x0,
        NULL, HFILL}
        },
		{ &hf_gtpv2_CauseTransport,
        {"Transport Layer Cause","gtpv2.CauseTransport",
        FT_UINT8, BASE_DEC, VALS(&s1ap_CauseTransport_vals),0x0,
        NULL, HFILL}
        },
		{ &hf_gtpv2_CauseNas,
        {"NAS Cause","gtpv2.CauseNas",
        FT_UINT8, BASE_DEC, VALS(&s1ap_CauseNas_vals),0x0,
        NULL, HFILL}
        },
		{ &hf_gtpv2_CauseMisc,
        {"Miscellaneous Cause","gtpv2.CauseMisc",
        FT_UINT8, BASE_DEC, VALS(&s1ap_CauseMisc_vals),0x0,
        NULL, HFILL}
        },
		{ &hf_gtpv2_target_type,
        {"Target Type","gtpv2.target_type",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &gtpv2_target_type_vals_ext,0x0,
        NULL, HFILL}
        },
		{&hf_gtpv2_macro_enodeb_id,
        {"Macro eNodeB ID","gtpv2.macro_enodeb_id",
        FT_UINT24, BASE_HEX, NULL,0x0fffff,
        NULL, HFILL}
        },
		{ &hf_gtpv2_CauseProtocol,
        {"Protocol Cause","gtpv2.CauseProtocol",
        FT_UINT8, BASE_DEC, VALS(&s1ap_CauseProtocol_vals),0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_apn_rest,
        {"APN Restriction", "gtpv2.apn_rest",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
        },
        {&hf_gtpv2_selec_mode,
        {"Selection Mode","gtpv2.selec_mode",
        FT_UINT8, BASE_DEC, VALS(gtpv2_selec_mode_vals),0x03,
        NULL, HFILL}
        },
        {&hf_gtpv2_bearer_control_mode,
        {"Bearer Control Mode","gtpv2.bearer_control_mode",
        FT_UINT8, BASE_DEC, VALS(gtpv2_bearer_control_mode_vals),0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_cng_rep_act,
        {"Change Reporting Action", "gtpv2.cng_rep_act",
        FT_UINT8, BASE_DEC, VALS(gtpv2_cng_rep_act_vals), 0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_node_type,
        {"Node Type", "gtpv2.node_type",
        FT_UINT8, BASE_DEC, VALS(gtpv2_node_type_vals), 0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_enterprise_id,
        {"Enterprise ID", "gtpv2.enterprise_id",
        FT_UINT16, BASE_DEC|BASE_EXT_STRING, &sminmpec_values_ext, 0x0,
        NULL, HFILL}
        },
        { &hf_gtpv2_address_digits,
            { "Address digits", "gtpv2.address_digits",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
		{ &hf_gtpv2_ti,
        {"Transaction Identifier", "gtpv2.ti",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
        },

     };

    static gint *ett_gtpv2_array[] = {
        &ett_gtpv2,
        &ett_gtpv2_flags,
        &ett_gtpv2_ie,
        &ett_gtpv2_bearer_ctx,
		&ett_gtpv2_PDN_conn,
    };

    proto_gtpv2 = proto_register_protocol("GPRS Tunneling Protocol V2", "GTPv2", "gtpv2");
    proto_register_field_array(proto_gtpv2, hf_gtpv2, array_length(hf_gtpv2));
    proto_register_subtree_array(ett_gtpv2_array, array_length(ett_gtpv2_array));
    /* AVP Code: 22 3GPP-User-Location-Info */
    dissector_add_uint("diameter.3gpp", 22, new_create_dissector_handle(dissect_diameter_3gpp_uli, proto_gtpv2));

    register_dissector("gtpv2", dissect_gtpv2, proto_gtpv2);
}

void
proto_reg_handoff_gtpv2(void)
{
	nas_eps_handle = find_dissector("nas-eps");
}
