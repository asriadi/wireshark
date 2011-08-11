/* autogenerated by pidl */

/* DO NOT EDIT
	This filter was automatically generated
	from frsrpc.idl and frsrpc.cnf.
	
	Pidl is a perl based IDL compiler for DCE/RPC idl files. 
	It is maintained by the Samba team, not the Wireshark team.
	Instructions on how to download and install Pidl can be 
	found at http://wiki.wireshark.org/Pidl
*/


#include "packet-dcerpc-misc.h"

#ifndef __PACKET_DCERPC_FRSRPC_H
#define __PACKET_DCERPC_FRSRPC_H

#define FRSRPC_CO_IFLAG_NONE	( 0x0000000 )

int frsrpc_dissect_struct_CommPktChunkGuidName(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_);
int frsrpc_dissect_struct_CommPktGSVN(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_);
int frsrpc_dissect_bitmap_CommPktCoCmdFlags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_);
int frsrpc_dissect_bitmap_CommPktCoCmdIFlags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_);
#define FRSRPC_CO_STATUS_CO_ENTERED_LOG (0x00000000)
#define FRSRPC_CO_STATUS_ALLOC_STAGING_LOCAL_CO (0x00000001)
#define FRSRPC_CO_STATUS_LOCAL_CO_STAGING_STARTED (0x00000002)
#define FRSRPC_CO_STATUS_LOCAL_CO_STAGING_COMPLETED (0x00000003)
#define FRSRPC_CO_STATUS_WAIT_RETRY_LOCAL_CO_STAGING (0x00000004)
#define FRSRPC_CO_STATUS_ALLOC_STAGING_REMOTE_CO (0x00000005)
#define FRSRPC_CO_STATUS_REMOTE_CO_STAGING_STARTED (0x00000006)
#define FRSRPC_CO_STATUS_REMOTE_CO_STAGING_COMPLETED (0x00000007)
#define FRSRPC_CO_STATUS_WAIT_RETRY_REMOTE_CO_STAGING (0x00000008)
#define FRSRPC_CO_STATUS_FILE_INSTALL_REQUESTED (0x00000009)
#define FRSRPC_CO_STATUS_FILE_INSTALL_STARTED (0x0000000A)
#define FRSRPC_CO_STATUS_FILE_INSTALL_COMPLETED (0x0000000B)
#define FRSRPC_CO_STATUS_FILE_INSTALL_WAIT_RETRY (0x0000000C)
#define FRSRPC_CO_STATUS_FILE_INSTALL_RETRYING (0x0000000D)
#define FRSRPC_CO_STATUS_FILE_INSTALL_RENAME_RETRYING (0x0000000E)
#define FRSRPC_CO_STATUS_FILE_INSTALL_DELETE_RETRYING (0x0000000F)
#define FRSRPC_CO_STATUS_CO_RECYCLED_FOR_ENUM (0x00000013)
#define FRSRPC_CO_STATUS_REQUEST_OUTBOUND_PROPAGATION (0x00000014)
#define FRSRPC_CO_STATUS_REQUEST_ACCEPTED_OUTBOUND_LOG (0x00000015)
#define FRSRPC_CO_STATUS_DB_STATE_UPDATE_STARTED (0x00000016)
#define FRSRPC_CO_STATUS_DB_STATE_UPDATE_COMPLETED (0x00000017)
#define FRSRPC_CO_STATUS_CO_ABORTED (0x00000018)
extern const value_string frsrpc_frsrpc_CommPktCoCmdStatus_vals[];
int frsrpc_dissect_enum_CommPktCoCmdStatus(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_);
int frsrpc_dissect_bitmap_CommPktCoCmdContentCmd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_);
#define FRSRPC_CO_LOCATION_FILE_CREATE (0x00000000)
#define FRSRPC_CO_LOCATION_DIR_CREATE (0x00000000|0x00000001)
#define FRSRPC_CO_LOCATION_FILE_DELETE (0x00000002)
#define FRSRPC_CO_LOCATION_DIR_DELETE (0x00000002|0x00000001)
#define FRSRPC_CO_LOCATION_FILE_MOVEIN (0x00000004)
#define FRSRPC_CO_LOCATION_DIR_MOVEIN (0x00000004|0x00000001)
#define FRSRPC_CO_LOCATION_FILE_MOVEIN2 (0x00000006)
#define FRSRPC_CO_LOCATION_DIR_MOVEIN2 (0x00000006|0x00000001)
#define FRSRPC_CO_LOCATION_FILE_MOVEOUT (0x00000008)
#define FRSRPC_CO_LOCATION_DIR_MOVEOUT (0x00000008|0x00000001)
#define FRSRPC_CO_LOCATION_FILE_MOVERS (0x0000000a)
#define FRSRPC_CO_LOCATION_DIR_MOVERS (0x0000000a|0x00000001)
#define FRSRPC_CO_LOCATION_FILE_MOVEDIR (0x0000000c)
#define FRSRPC_CO_LOCATION_DIR_MOVEDIR (0x0000000c|0x00000001)
#define FRSRPC_CO_LOCATION_FILE_NO_CMD (0x0000000e)
#define FRSRPC_CO_LOCATION_DIR_NO_CMD (0x0000000e|0x00000001)
extern const value_string frsrpc_frsrpc_CommPktCoCmdLocationCmd_vals[];
int frsrpc_dissect_enum_CommPktCoCmdLocationCmd(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_);
int frsrpc_dissect_struct_CommPktChangeOrderCommand(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_);
#define FRSRPC_DATA_EXTENSION_TERMINATOR (0x00000000)
#define FRSRPC_DATA_EXTENSION_MD5_CHECKSUM (0x00000001)
#define FRSRPC_DATA_EXTENSION_RETRY_TIMEOUT (0x00000002)
extern const value_string frsrpc_frsrpc_CommPktDataExtensionType_vals[];
int frsrpc_dissect_enum_CommPktDataExtensionType(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_);
int frsrpc_dissect_struct_CommPktDataExtensionChecksum(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_);
int frsrpc_dissect_struct_CommPktDataExtensionRetryTimeout(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_);
#define FRSRPC_CO_RECORD_EXTENSION_VERSION_WIN2K (0x0000)
#define FRSRPC_CO_RECORD_EXTENSION_VERSION_1 (0x0001)
extern const value_string frsrpc_frsrpc_CommPktCoRecordExtensionMajor_vals[];
int frsrpc_dissect_enum_CommPktCoRecordExtensionMajor(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_);
int frsrpc_dissect_struct_CommPktCoRecordExtensionWin2k(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_);
int frsrpc_dissect_struct_CommPktChangeOrderRecordExtension(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_);
#define FRSRPC_COMMAND_REMOTE_CO (0x00000218)
#define FRSRPC_COMMAND_RECEIVING_STATE (0x00000238)
#define FRSRPC_COMMAND_REMOTE_CO_DONE (0x00000250)
#define FRSRPC_COMMAND_ABORT_FETCH (0x00000246)
#define FRSRPC_COMMAND_RETRY_FETCH (0x00000244)
#define FRSRPC_COMMAND_NEED_JOIN (0x00000121)
#define FRSRPC_COMMAND_START_JOIN (0x00000122)
#define FRSRPC_COMMAND_JOINING (0x00000130)
#define FRSRPC_COMMAND_JOINED (0x00000128)
#define FRSRPC_COMMAND_UNJOIN_REMOTE (0x00000148)
#define FRSRPC_COMMAND_WJOIN_DONE (0x00000136)
#define FRSRPC_COMMAND_SEND_STAGE (0x00000228)
extern const value_string frsrpc_frsrpc_CommPktCommand_vals[];
int frsrpc_dissect_enum_CommPktCommand(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_);
#define FRSRPC_COMM_PKT_CHUNK_BOP (0x0001)
#define FRSRPC_COMM_PKT_CHUNK_COMMAND (0x0002)
#define FRSRPC_COMM_PKT_CHUNK_TO (0x0003)
#define FRSRPC_COMM_PKT_CHUNK_FROM (0x0004)
#define FRSRPC_COMM_PKT_CHUNK_REPLICA (0x0005)
#define FRSRPC_COMM_PKT_CHUNK_CONNECTION (0x0008)
#define FRSRPC_COMM_PKT_CHUNK_JOIN_GUID (0x0006)
#define FRSRPC_COMM_PKT_CHUNK_LAST_JOIN_TIME (0x0012)
#define FRSRPC_COMM_PKT_CHUNK_VVECTOR (0x0007)
#define FRSRPC_COMM_PKT_CHUNK_JOIN_TIME (0x0011)
#define FRSRPC_COMM_PKT_CHUNK_REPLICA_VERSION_GUID (0x0014)
#define FRSRPC_COMM_PKT_CHUNK_COMPRESSION_GUID (0x0018)
#define FRSRPC_COMM_PKT_CHUNK_BLOCK (0x0009)
#define FRSRPC_COMM_PKT_CHUNK_BLOCK_SIZE (0x000A)
#define FRSRPC_COMM_PKT_CHUNK_FILE_SIZE (0x000B)
#define FRSRPC_COMM_PKT_CHUNK_FILE_OFFSET (0x000C)
#define FRSRPC_COMM_PKT_CHUNK_GVSN (0x000E)
#define FRSRPC_COMM_PKT_CHUNK_CO_GUID (0x000F)
#define FRSRPC_COMM_PKT_CHUNK_CO_SEQUENCE_NUMBER (0x0010)
#define FRSRPC_COMM_PKT_CHUNK_REMOTE_CO (0x000D)
#define FRSRPC_COMM_PKT_CHUNK_CO_EXT_WIN2K (0x0016)
#define FRSRPC_COMM_PKT_CHUNK_CO_EXTENTION_2 (0x0017)
#define FRSRPC_COMM_PKT_CHUNK_EOP (0x0013)
extern const value_string frsrpc_frsrpc_CommPktChunkType_vals[];
int frsrpc_dissect_enum_CommPktChunkType(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_);
int frsrpc_dissect_struct_CommPktChunk(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_);
#define FRSRPC_COMM_PKT_MAJOR_0 (0x00000000)
extern const value_string frsrpc_frsrpc_CommPktMajor_vals[];
int frsrpc_dissect_enum_CommPktMajor(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_);
#define FRSRPC_COMM_PKT_MINOR_0 (0x00000000)
#define FRSRPC_COMM_PKT_MINOR_1 (0x00000001)
#define FRSRPC_COMM_PKT_MINOR_2 (0x00000002)
#define FRSRPC_COMM_PKT_MINOR_3 (0x00000003)
#define FRSRPC_COMM_PKT_MINOR_4 (0x00000004)
#define FRSRPC_COMM_PKT_MINOR_5 (0x00000005)
#define FRSRPC_COMM_PKT_MINOR_6 (0x00000006)
#define FRSRPC_COMM_PKT_MINOR_7 (0x00000007)
#define FRSRPC_COMM_PKT_MINOR_8 (0x00000008)
#define FRSRPC_COMM_PKT_MINOR_9 (0x00000009)
extern const value_string frsrpc_frsrpc_CommPktMinor_vals[];
int frsrpc_dissect_enum_CommPktMinor(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_);
int frsrpc_dissect_struct_FrsSendCommPktReq(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 param _U_);
#define FRSRPC_PARENT_AUTH_LEVEL_ENCRYPTED_KERBEROS (0x00000000)
#define FRSRPC_PARENT_AUTH_LEVEL_NO_AUTHENTICATION (0x00000001)
extern const value_string frsrpc_frsrpc_PartnerAuthLevel_vals[];
int frsrpc_dissect_enum_PartnerAuthLevel(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, guint8 *drep _U_, int hf_index _U_, guint32 *param _U_);
#endif /* __PACKET_DCERPC_FRSRPC_H */
