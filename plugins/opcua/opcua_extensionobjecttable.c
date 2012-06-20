/******************************************************************************
** $Id$
**
** Copyright (C) 2006-2009 ascolab GmbH. All Rights Reserved.
** Web: http://www.ascolab.com
**
** This program is free software; you can redistribute it and/or
** modify it under the terms of the GNU General Public License
** as published by the Free Software Foundation; either version 2
** of the License, or (at your option) any later version.
**
** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
**
** Project: OpcUa Wireshark Plugin
**
** Description: Service table and service dispatcher.
**
** This file was autogenerated on 22.11.2010.
** DON'T MODIFY THIS FILE!
** XXX - well, except that you may have to.  See the README.
**
******************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "opcua_simpletypes.h"
#include "opcua_complextypeparser.h"
#include "opcua_extensionobjectids.h"
#include "opcua_hfindeces.h"

ExtensionObjectParserEntry g_arExtensionObjectParserTable[] = {
    { OpcUaId_Node_Encoding_DefaultBinary, parseNode, "Node" },
    { OpcUaId_ObjectNode_Encoding_DefaultBinary, parseObjectNode, "ObjectNode" },
    { OpcUaId_ObjectTypeNode_Encoding_DefaultBinary, parseObjectTypeNode, "ObjectTypeNode" },
    { OpcUaId_VariableNode_Encoding_DefaultBinary, parseVariableNode, "VariableNode" },
    { OpcUaId_VariableTypeNode_Encoding_DefaultBinary, parseVariableTypeNode, "VariableTypeNode" },
    { OpcUaId_ReferenceTypeNode_Encoding_DefaultBinary, parseReferenceTypeNode, "ReferenceTypeNode" },
    { OpcUaId_MethodNode_Encoding_DefaultBinary, parseMethodNode, "MethodNode" },
    { OpcUaId_ViewNode_Encoding_DefaultBinary, parseViewNode, "ViewNode" },
    { OpcUaId_DataTypeNode_Encoding_DefaultBinary, parseDataTypeNode, "DataTypeNode" },
    { OpcUaId_ReferenceNode_Encoding_DefaultBinary, parseReferenceNode, "ReferenceNode" },
    { OpcUaId_Argument_Encoding_DefaultBinary, parseArgument, "Argument" },
    { OpcUaId_TimeZoneDataType_Encoding_DefaultBinary, parseTimeZoneDataType, "TimeZoneDataType" },
    { OpcUaId_StatusResult_Encoding_DefaultBinary, parseStatusResult, "StatusResult" },
    { OpcUaId_UserTokenPolicy_Encoding_DefaultBinary, parseUserTokenPolicy, "UserTokenPolicy" },
    { OpcUaId_ApplicationDescription_Encoding_DefaultBinary, parseApplicationDescription, "ApplicationDescription" },
    { OpcUaId_EndpointDescription_Encoding_DefaultBinary, parseEndpointDescription, "EndpointDescription" },
    { OpcUaId_UserIdentityToken_Encoding_DefaultBinary, parseUserIdentityToken, "UserIdentityToken" },
    { OpcUaId_UserNameIdentityToken_Encoding_DefaultBinary, parseUserNameIdentityToken, "UserNameIdentityToken" },
    { OpcUaId_X509IdentityToken_Encoding_DefaultBinary, parseX509IdentityToken, "X509IdentityToken" },
    { OpcUaId_IssuedIdentityToken_Encoding_DefaultBinary, parseIssuedIdentityToken, "IssuedIdentityToken" },
    { OpcUaId_EndpointConfiguration_Encoding_DefaultBinary, parseEndpointConfiguration, "EndpointConfiguration" },
    { OpcUaId_SupportedProfile_Encoding_DefaultBinary, parseSupportedProfile, "SupportedProfile" },
    { OpcUaId_BuildInfo_Encoding_DefaultBinary, parseBuildInfo, "BuildInfo" },
    { OpcUaId_SoftwareCertificate_Encoding_DefaultBinary, parseSoftwareCertificate, "SoftwareCertificate" },
    { OpcUaId_SignedSoftwareCertificate_Encoding_DefaultBinary, parseSignedSoftwareCertificate, "SignedSoftwareCertificate" },
    { OpcUaId_NodeAttributes_Encoding_DefaultBinary, parseNodeAttributes, "NodeAttributes" },
    { OpcUaId_ObjectAttributes_Encoding_DefaultBinary, parseObjectAttributes, "ObjectAttributes" },
    { OpcUaId_VariableAttributes_Encoding_DefaultBinary, parseVariableAttributes, "VariableAttributes" },
    { OpcUaId_MethodAttributes_Encoding_DefaultBinary, parseMethodAttributes, "MethodAttributes" },
    { OpcUaId_ObjectTypeAttributes_Encoding_DefaultBinary, parseObjectTypeAttributes, "ObjectTypeAttributes" },
    { OpcUaId_VariableTypeAttributes_Encoding_DefaultBinary, parseVariableTypeAttributes, "VariableTypeAttributes" },
    { OpcUaId_ReferenceTypeAttributes_Encoding_DefaultBinary, parseReferenceTypeAttributes, "ReferenceTypeAttributes" },
    { OpcUaId_DataTypeAttributes_Encoding_DefaultBinary, parseDataTypeAttributes, "DataTypeAttributes" },
    { OpcUaId_ViewAttributes_Encoding_DefaultBinary, parseViewAttributes, "ViewAttributes" },
    { OpcUaId_AddNodesItem_Encoding_DefaultBinary, parseAddNodesItem, "AddNodesItem" },
    { OpcUaId_AddReferencesItem_Encoding_DefaultBinary, parseAddReferencesItem, "AddReferencesItem" },
    { OpcUaId_DeleteNodesItem_Encoding_DefaultBinary, parseDeleteNodesItem, "DeleteNodesItem" },
    { OpcUaId_DeleteReferencesItem_Encoding_DefaultBinary, parseDeleteReferencesItem, "DeleteReferencesItem" },
    { OpcUaId_RequestHeader_Encoding_DefaultBinary, parseRequestHeader, "RequestHeader" },
    { OpcUaId_ResponseHeader_Encoding_DefaultBinary, parseResponseHeader, "ResponseHeader" },
    { OpcUaId_ServiceFault_Encoding_DefaultBinary, parseServiceFault, "ServiceFault" },
    { OpcUaId_ScalarTestType_Encoding_DefaultBinary, parseScalarTestType, "ScalarTestType" },
    { OpcUaId_ArrayTestType_Encoding_DefaultBinary, parseArrayTestType, "ArrayTestType" },
    { OpcUaId_CompositeTestType_Encoding_DefaultBinary, parseCompositeTestType, "CompositeTestType" },
    { OpcUaId_RegisteredServer_Encoding_DefaultBinary, parseRegisteredServer, "RegisteredServer" },
    { OpcUaId_ChannelSecurityToken_Encoding_DefaultBinary, parseChannelSecurityToken, "ChannelSecurityToken" },
    { OpcUaId_SignatureData_Encoding_DefaultBinary, parseSignatureData, "SignatureData" },
    { OpcUaId_AddNodesResult_Encoding_DefaultBinary, parseAddNodesResult, "AddNodesResult" },
    { OpcUaId_ViewDescription_Encoding_DefaultBinary, parseViewDescription, "ViewDescription" },
    { OpcUaId_BrowseDescription_Encoding_DefaultBinary, parseBrowseDescription, "BrowseDescription" },
    { OpcUaId_ReferenceDescription_Encoding_DefaultBinary, parseReferenceDescription, "ReferenceDescription" },
    { OpcUaId_BrowseResult_Encoding_DefaultBinary, parseBrowseResult, "BrowseResult" },
    { OpcUaId_RelativePathElement_Encoding_DefaultBinary, parseRelativePathElement, "RelativePathElement" },
    { OpcUaId_RelativePath_Encoding_DefaultBinary, parseRelativePath, "RelativePath" },
    { OpcUaId_BrowsePath_Encoding_DefaultBinary, parseBrowsePath, "BrowsePath" },
    { OpcUaId_BrowsePathTarget_Encoding_DefaultBinary, parseBrowsePathTarget, "BrowsePathTarget" },
    { OpcUaId_BrowsePathResult_Encoding_DefaultBinary, parseBrowsePathResult, "BrowsePathResult" },
    { OpcUaId_QueryDataDescription_Encoding_DefaultBinary, parseQueryDataDescription, "QueryDataDescription" },
    { OpcUaId_NodeTypeDescription_Encoding_DefaultBinary, parseNodeTypeDescription, "NodeTypeDescription" },
    { OpcUaId_QueryDataSet_Encoding_DefaultBinary, parseQueryDataSet, "QueryDataSet" },
    { OpcUaId_NodeReference_Encoding_DefaultBinary, parseNodeReference, "NodeReference" },
    { OpcUaId_ContentFilterElement_Encoding_DefaultBinary, parseContentFilterElement, "ContentFilterElement" },
    { OpcUaId_ContentFilter_Encoding_DefaultBinary, parseContentFilter, "ContentFilter" },
    { OpcUaId_ElementOperand_Encoding_DefaultBinary, parseElementOperand, "ElementOperand" },
    { OpcUaId_LiteralOperand_Encoding_DefaultBinary, parseLiteralOperand, "LiteralOperand" },
    { OpcUaId_AttributeOperand_Encoding_DefaultBinary, parseAttributeOperand, "AttributeOperand" },
    { OpcUaId_SimpleAttributeOperand_Encoding_DefaultBinary, parseSimpleAttributeOperand, "SimpleAttributeOperand" },
    { OpcUaId_ContentFilterElementResult_Encoding_DefaultBinary, parseContentFilterElementResult, "ContentFilterElementResult" },
    { OpcUaId_ContentFilterResult_Encoding_DefaultBinary, parseContentFilterResult, "ContentFilterResult" },
    { OpcUaId_ParsingResult_Encoding_DefaultBinary, parseParsingResult, "ParsingResult" },
    { OpcUaId_ReadValueId_Encoding_DefaultBinary, parseReadValueId, "ReadValueId" },
    { OpcUaId_HistoryReadValueId_Encoding_DefaultBinary, parseHistoryReadValueId, "HistoryReadValueId" },
    { OpcUaId_HistoryReadResult_Encoding_DefaultBinary, parseHistoryReadResult, "HistoryReadResult" },
    { OpcUaId_ReadEventDetails_Encoding_DefaultBinary, parseReadEventDetails, "ReadEventDetails" },
    { OpcUaId_ReadRawModifiedDetails_Encoding_DefaultBinary, parseReadRawModifiedDetails, "ReadRawModifiedDetails" },
    { OpcUaId_ReadProcessedDetails_Encoding_DefaultBinary, parseReadProcessedDetails, "ReadProcessedDetails" },
    { OpcUaId_ReadAtTimeDetails_Encoding_DefaultBinary, parseReadAtTimeDetails, "ReadAtTimeDetails" },
    { OpcUaId_HistoryData_Encoding_DefaultBinary, parseHistoryData, "HistoryData" },
    { OpcUaId_HistoryEvent_Encoding_DefaultBinary, parseHistoryEvent, "HistoryEvent" },
    { OpcUaId_WriteValue_Encoding_DefaultBinary, parseWriteValue, "WriteValue" },
    { OpcUaId_HistoryUpdateDetails_Encoding_DefaultBinary, parseHistoryUpdateDetails, "HistoryUpdateDetails" },
    { OpcUaId_UpdateDataDetails_Encoding_DefaultBinary, parseUpdateDataDetails, "UpdateDataDetails" },
    { OpcUaId_UpdateEventDetails_Encoding_DefaultBinary, parseUpdateEventDetails, "UpdateEventDetails" },
    { OpcUaId_DeleteRawModifiedDetails_Encoding_DefaultBinary, parseDeleteRawModifiedDetails, "DeleteRawModifiedDetails" },
    { OpcUaId_DeleteAtTimeDetails_Encoding_DefaultBinary, parseDeleteAtTimeDetails, "DeleteAtTimeDetails" },
    { OpcUaId_DeleteEventDetails_Encoding_DefaultBinary, parseDeleteEventDetails, "DeleteEventDetails" },
    { OpcUaId_HistoryUpdateResult_Encoding_DefaultBinary, parseHistoryUpdateResult, "HistoryUpdateResult" },
    { OpcUaId_HistoryUpdateEventResult_Encoding_DefaultBinary, parseHistoryUpdateEventResult, "HistoryUpdateEventResult" },
    { OpcUaId_CallMethodRequest_Encoding_DefaultBinary, parseCallMethodRequest, "CallMethodRequest" },
    { OpcUaId_CallMethodResult_Encoding_DefaultBinary, parseCallMethodResult, "CallMethodResult" },
    { OpcUaId_DataChangeFilter_Encoding_DefaultBinary, parseDataChangeFilter, "DataChangeFilter" },
    { OpcUaId_EventFilter_Encoding_DefaultBinary, parseEventFilter, "EventFilter" },
    { OpcUaId_AggregateConfiguration_Encoding_DefaultBinary, parseAggregateConfiguration, "AggregateConfiguration" },
    { OpcUaId_AggregateFilter_Encoding_DefaultBinary, parseAggregateFilter, "AggregateFilter" },
    { OpcUaId_EventFilterResult_Encoding_DefaultBinary, parseEventFilterResult, "EventFilterResult" },
    { OpcUaId_AggregateFilterResult_Encoding_DefaultBinary, parseAggregateFilterResult, "AggregateFilterResult" },
    { OpcUaId_MonitoringParameters_Encoding_DefaultBinary, parseMonitoringParameters, "MonitoringParameters" },
    { OpcUaId_MonitoredItemCreateRequest_Encoding_DefaultBinary, parseMonitoredItemCreateRequest, "MonitoredItemCreateRequest" },
    { OpcUaId_MonitoredItemCreateResult_Encoding_DefaultBinary, parseMonitoredItemCreateResult, "MonitoredItemCreateResult" },
    { OpcUaId_MonitoredItemModifyRequest_Encoding_DefaultBinary, parseMonitoredItemModifyRequest, "MonitoredItemModifyRequest" },
    { OpcUaId_MonitoredItemModifyResult_Encoding_DefaultBinary, parseMonitoredItemModifyResult, "MonitoredItemModifyResult" },
    { OpcUaId_NotificationMessage_Encoding_DefaultBinary, parseNotificationMessage, "NotificationMessage" },
    { OpcUaId_DataChangeNotification_Encoding_DefaultBinary, parseDataChangeNotification, "DataChangeNotification" },
    { OpcUaId_MonitoredItemNotification_Encoding_DefaultBinary, parseMonitoredItemNotification, "MonitoredItemNotification" },
    { OpcUaId_EventNotificationList_Encoding_DefaultBinary, parseEventNotificationList, "EventNotificationList" },
    { OpcUaId_EventFieldList_Encoding_DefaultBinary, parseEventFieldList, "EventFieldList" },
    { OpcUaId_HistoryEventFieldList_Encoding_DefaultBinary, parseHistoryEventFieldList, "HistoryEventFieldList" },
    { OpcUaId_StatusChangeNotification_Encoding_DefaultBinary, parseStatusChangeNotification, "StatusChangeNotification" },
    { OpcUaId_SubscriptionAcknowledgement_Encoding_DefaultBinary, parseSubscriptionAcknowledgement, "SubscriptionAcknowledgement" },
    { OpcUaId_TransferResult_Encoding_DefaultBinary, parseTransferResult, "TransferResult" },
    { OpcUaId_RedundantServerDataType_Encoding_DefaultBinary, parseRedundantServerDataType, "RedundantServerDataType" },
    { OpcUaId_SamplingIntervalDiagnosticsDataType_Encoding_DefaultBinary, parseSamplingIntervalDiagnosticsDataType, "SamplingIntervalDiagnosticsDataType" },
    { OpcUaId_ServerDiagnosticsSummaryDataType_Encoding_DefaultBinary, parseServerDiagnosticsSummaryDataType, "ServerDiagnosticsSummaryDataType" },
    { OpcUaId_ServerStatusDataType_Encoding_DefaultBinary, parseServerStatusDataType, "ServerStatusDataType" },
    { OpcUaId_SessionDiagnosticsDataType_Encoding_DefaultBinary, parseSessionDiagnosticsDataType, "SessionDiagnosticsDataType" },
    { OpcUaId_SessionSecurityDiagnosticsDataType_Encoding_DefaultBinary, parseSessionSecurityDiagnosticsDataType, "SessionSecurityDiagnosticsDataType" },
    { OpcUaId_ServiceCounterDataType_Encoding_DefaultBinary, parseServiceCounterDataType, "ServiceCounterDataType" },
    { OpcUaId_SubscriptionDiagnosticsDataType_Encoding_DefaultBinary, parseSubscriptionDiagnosticsDataType, "SubscriptionDiagnosticsDataType" },
    { OpcUaId_ModelChangeStructureDataType_Encoding_DefaultBinary, parseModelChangeStructureDataType, "ModelChangeStructureDataType" },
    { OpcUaId_SemanticChangeStructureDataType_Encoding_DefaultBinary, parseSemanticChangeStructureDataType, "SemanticChangeStructureDataType" },
    { OpcUaId_Range_Encoding_DefaultBinary, parseRange, "Range" },
    { OpcUaId_EUInformation_Encoding_DefaultBinary, parseEUInformation, "EUInformation" },
    { OpcUaId_Annotation_Encoding_DefaultBinary, parseAnnotation, "Annotation" },
    { OpcUaId_ProgramDiagnosticDataType_Encoding_DefaultBinary, parseProgramDiagnosticDataType, "ProgramDiagnosticDataType" },
};
const int g_NumTypes = sizeof(g_arExtensionObjectParserTable) / sizeof(ExtensionObjectParserEntry);

/** Dispatch all extension objects to a special parser function. */
void dispatchExtensionObjectType(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int TypeId)
{
    gint    iOffset = *pOffset;
    int     index = 0;
    int     bFound = 0;
    gint32  iLen = 0;

    /* get the length of the body */
    iLen = tvb_get_letohl(tvb, iOffset);
    iOffset += 4;

    while (index < g_NumTypes)
    {
        if (g_arExtensionObjectParserTable[index].iRequestId == TypeId)
        {
            bFound = 1;
            (*g_arExtensionObjectParserTable[index].pParser)(tree, tvb, &iOffset, g_arExtensionObjectParserTable[index].typeName);
            break;
        }
        index++;
    }

    /* display contained object as ByteString if unknown type */
    if (bFound == 0)
    {
        if (iLen == -1)
        {
            proto_tree_add_text(tree, tvb, iOffset, 0, "[OpcUa Null ByteString]");
        }
        else if (iLen >= 0)
        {
            proto_tree_add_item(tree, hf_opcua_ByteString, tvb, iOffset, iLen, ENC_NA);
            iOffset += iLen; /* eat the whole bytestring */
        }
        else
        {
            char *szValue = ep_strdup_printf("[Invalid ByteString] Invalid length: %d", iLen);
            proto_tree_add_text(tree, tvb, iOffset, 0, "%s", szValue);
        }
    }

    *pOffset = iOffset;
}

