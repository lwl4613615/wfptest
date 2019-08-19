#define NDIS61 
#include "ioctl.h"
#include <ntddk.h>
#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union
#pragma warning(disable:4995)
#include <fwpsk.h>
#pragma warning(pop)
#include <ndis.h>
#include <fwpmk.h>
#include <limits.h>
#include <ws2ipdef.h>
#include <in6addr.h>
#include <ip2string.h>
#include <strsafe.h>
#define INITGUID
#include <guiddef.h>
#define bool BOOLEAN
#define true TRUE 
#define false FALSE
#define DEVICE_NAME L"\\Device\\WFP_TEST"
#define DEVICE_DOSNAME L"\\DosDevices\\WFP_TEST"
#define kmalloc(_s) ExAllocatePoolWithTag(NonPagedPool, _s, 'SYSQ')
#define kfree(_p) ExFreePool(_p)


DEFINE_GUID // {6812FC83-7D3E-499a-A012-55E0D85F348B}
(
	GUID_ALE_AUTH_CONNECT_CALLOUT_V4,
	0x6812fc83,
	0x7d3e,
	0x499a,
	0xa0, 0x12, 0x55, 0xe0, 0xd8, 0x5f, 0x34, 0x8b
);

PDEVICE_OBJECT  gDevObj;

HANDLE	gEngineHandle = 0;
HANDLE	gInjectHandle = 0;
//CalloutId
UINT32	gAleConnectCalloutId = 0;
//FilterId
UINT64	gAleConnectFilterId = 0;

LIST_ENTRY gPath_list;
//�ں˷ַ�����

NTSTATUS DispatchCommon(PDEVICE_OBJECT pObject, PIRP pIrp) {

	UNREFERENCED_PARAMETER(pObject);
	// ����ɹ��Ƿ��ظ�R3��,��ΪR3Ҳ�ڵ����IRP����Ľ��
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	// ��ʾIo��һЩ������Ϣ.
	// �����ڶ�д����ʱ��ʾʵ�ʶ�д���ֽ���
	// �������ط������и������˼
	pIrp->IoStatus.Information = 0;

	// ���������IRP
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	// ���return����ֵ�ǹ�IOManagerʹ��,��IO����ṩ������
	return STATUS_SUCCESS;
}
NTSTATUS DispatchIoctrl(PDEVICE_OBJECT pObject, PIRP pIrp) {

	UNREFERENCED_PARAMETER(pObject);

	ULONG uControlCode = 0;
	PVOID pInputBuff = NULL;
	PVOID pOutputBuffer = NULL;
	ULONG uInputLength = 0;
	ULONG uOutputLength = 0;
	PIO_STACK_LOCATION pStack = NULL;

	// ��Ȼ��R3��,Input��Output��2��Buffer,����R0����ͬһ��
	pInputBuff = pOutputBuffer = pIrp->AssociatedIrp.SystemBuffer;

	pStack = IoGetCurrentIrpStackLocation(pIrp);
	uInputLength = pStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutputLength = pStack->Parameters.DeviceIoControl.OutputBufferLength;

	uControlCode = pStack->Parameters.DeviceIoControl.IoControlCode;

	switch (uControlCode)
	{
	case IOCTL_ADD_PATH:
		DbgPrint("ADD PATH IoControl\n");
		break; 
	case IOCTL_DELETE_PATH:
		DbgPrint("DELETE PATH IoControl \n");
		break;
	default:
		DbgPrint("Unknown IoControl\n");
	}

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

/*
	���������ص�����ûɶ��
*/
NTSTATUS NTAPI WallNotifyFn
(
	IN FWPS_CALLOUT_NOTIFY_TYPE  notifyType,
	IN const GUID* filterKey,
	IN const FWPS_FILTER* filter
)
{
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(filterKey);
	(notifyType);
	return STATUS_SUCCESS;
}

VOID NTAPI WallFlowDeleteFn
(
	IN UINT16  layerId,
	IN UINT32  calloutId,
	IN UINT64  flowContext
)
{
	UNREFERENCED_PARAMETER(layerId);
	UNREFERENCED_PARAMETER(calloutId);
	UNREFERENCED_PARAMETER(flowContext);
	return;
}

//Э�����תΪ����
char* ProtocolIdToName(UINT16 id)
{
	char* ProtocolName = kmalloc(16);
	switch (id)	//http://www.ietf.org/rfc/rfc1700.txt
	{
	case 1:
		strcpy_s(ProtocolName, 4 + 1, "ICMP");
		break;
	case 2:
		strcpy_s(ProtocolName, 4 + 1, "IGMP");
		break;
	case 6:
		strcpy_s(ProtocolName, 3 + 1, "TCP");
		break;
	case 17:
		strcpy_s(ProtocolName, 3 + 1, "UDP");
		break;
	case 27:
		strcpy_s(ProtocolName, 3 + 1, "RDP");
		break;
	default:
		strcpy_s(ProtocolName, 7 + 1, "UNKNOWN");
		break;
	}
	return ProtocolName;
}

//����Ҫ�Ĺ��˺���
//http://msdn.microsoft.com/en-us/library/windows/hardware/ff551238(v=vs.85).aspx
void NTAPI WallALEConnectClassify
(
	IN const FWPS_INCOMING_VALUES0* inFixedValues,
	IN const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	IN OUT void* layerData,
	IN const void* classifyContext,
	IN const FWPS_FILTER* filter,
	IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT* classifyOut
)
{
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(layerData);
	char* ProtocolName = NULL;
	DWORD LocalIp, RemoteIP;
	LocalIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
	RemoteIP = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
	ProtocolName = ProtocolIdToName(inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint16);
	DbgPrint("[WFP]IRQL=%d;PID=%ld;Path=%S;Local=%u.%u.%u.%u:%d;Remote=%u.%u.%u.%u:%d;Protocol=%s\n",
		(USHORT)KeGetCurrentIrql(),
		(DWORD)(inMetaValues->processId),
		(PWCHAR)inMetaValues->processPath->data,	//NULL,//
		(LocalIp >> 24) & 0xFF, (LocalIp >> 16) & 0xFF, (LocalIp >> 8) & 0xFF, LocalIp & 0xFF,
		inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16,
		(RemoteIP >> 24) & 0xFF, (RemoteIP >> 16) & 0xFF, (RemoteIP >> 8) & 0xFF, RemoteIP & 0xFF,
		inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16,
		ProtocolName);
	kfree(ProtocolName);
	//���������·�����жϣ���������Ǿܾ��Ľ��̾ͽ��оܾ�����������ͷ���
	classifyOut->actionType = FWP_ACTION_PERMIT;//��������
	//��ֹIE���������á��ж����͡�ΪFWP_ACTION_BLOCK��
	// if(wcsstr((PWCHAR)inMetaValues->processPath->data,L"iexplore.exe"))
	// {
	// classifyOut->actionType = FWP_ACTION_BLOCK;
	// classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	// classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
	// }
	return;
}

NTSTATUS RegisterCalloutForLayer
(
	IN const GUID* layerKey,
	IN const GUID* calloutKey,
	IN FWPS_CALLOUT_CLASSIFY_FN classifyFn,
	IN FWPS_CALLOUT_NOTIFY_FN notifyFn,
	IN FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteNotifyFn,
	OUT UINT32* calloutId,
	OUT UINT64* filterId
)
{
	NTSTATUS        status = STATUS_SUCCESS;
	FWPS_CALLOUT    sCallout = { 0 };
	FWPM_FILTER     mFilter = { 0 };
	FWPM_FILTER_CONDITION mFilter_condition[1] = { 0 };
	FWPM_CALLOUT    mCallout = { 0 };
	FWPM_DISPLAY_DATA mDispData = { 0 };
	BOOLEAN         bCalloutRegistered = FALSE;
	sCallout.calloutKey = *calloutKey;
	sCallout.classifyFn = classifyFn;
	sCallout.flowDeleteFn = flowDeleteNotifyFn;
	sCallout.notifyFn = notifyFn;
	//Ҫʹ���ĸ��豸����ע��
	status = FwpsCalloutRegister(gDevObj, &sCallout, calloutId);
	if (!NT_SUCCESS(status))
		goto exit;
	bCalloutRegistered = TRUE;
	mDispData.name = L"WFP TEST";
	mDispData.description = L"TESLA.ANGELA's WFP TEST";
	//�����Ȥ������
	mCallout.applicableLayer = *layerKey;
	//�����Ȥ�����ݵ�GUID
	mCallout.calloutKey = *calloutKey;
	mCallout.displayData = mDispData;
	//��ӻص�����
	status = FwpmCalloutAdd(gEngineHandle, &mCallout, NULL, NULL);
	if (!NT_SUCCESS(status))
		goto exit;
	mFilter.action.calloutKey = *calloutKey;
	//��callout�����
	mFilter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	mFilter.displayData.name = L"WFP TEST";
	mFilter.displayData.description = L"TESLA.ANGELA's WFP TEST";
	mFilter.layerKey = *layerKey;
	mFilter.numFilterConditions = 0;
	mFilter.filterCondition = mFilter_condition;
	mFilter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
	mFilter.weight.type = FWP_EMPTY;
	//��ӹ�����
	status = FwpmFilterAdd(gEngineHandle, &mFilter, NULL, filterId);
	if (!NT_SUCCESS(status))
		goto exit;
exit:
	if (!NT_SUCCESS(status))
	{
		if (bCalloutRegistered)
		{
			FwpsCalloutUnregisterById(*calloutId);
		}
	}
	return status;
}

NTSTATUS WallRegisterCallouts()
{
	NTSTATUS    status = STATUS_SUCCESS;
	BOOLEAN     bInTransaction = FALSE;
	BOOLEAN     bEngineOpened = FALSE;
	FWPM_SESSION session = { 0 };
	session.flags = FWPM_SESSION_FLAG_DYNAMIC;
	//����WFP����
	status = FwpmEngineOpen(NULL,
		RPC_C_AUTHN_WINNT,
		NULL,
		&session,
		&gEngineHandle);
	if (!NT_SUCCESS(status))
		goto exit;
	bEngineOpened = TRUE;
	//ȷ�Ϲ���Ȩ��
	status = FwpmTransactionBegin(gEngineHandle, 0);
	if (!NT_SUCCESS(status))
		goto exit;
	bInTransaction = TRUE;
	//ע��ص�����
	status = RegisterCalloutForLayer(
		&FWPM_LAYER_ALE_AUTH_CONNECT_V4,
		&GUID_ALE_AUTH_CONNECT_CALLOUT_V4,
		WallALEConnectClassify,
		WallNotifyFn,
		WallFlowDeleteFn,
		&gAleConnectCalloutId,
		&gAleConnectFilterId);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("RegisterCalloutForLayer-FWPM_LAYER_ALE_AUTH_CONNECT_V4 failed!\n");
		goto exit;
	}
	//ȷ���������ݲ��ύ���ûص�������ʽ��������
	status = FwpmTransactionCommit(gEngineHandle);
	if (!NT_SUCCESS(status))
		goto exit;
	bInTransaction = FALSE;
exit:
	if (!NT_SUCCESS(status))
	{
		if (bInTransaction)
		{
			FwpmTransactionAbort(gEngineHandle);
		}
		if (bEngineOpened)
		{
			FwpmEngineClose(gEngineHandle);
			gEngineHandle = 0;
		}
	}
	return status;
}

NTSTATUS WallUnRegisterCallouts()
{
	if (gEngineHandle != 0)
	{
		//ɾ��FilterId
		FwpmFilterDeleteById(gEngineHandle, gAleConnectFilterId);
		//ɾ��CalloutId
		FwpmCalloutDeleteById(gEngineHandle, gAleConnectCalloutId);
		//���FilterId
		gAleConnectFilterId = 0;
		//��ע��CalloutId
		FwpsCalloutUnregisterById(gAleConnectCalloutId);
		//���CalloutId
		gAleConnectCalloutId = 0;
		//�ر�����
		FwpmEngineClose(gEngineHandle);
		gEngineHandle = 0;
	}
	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT driverObject)
{
	UNREFERENCED_PARAMETER(driverObject);
	NTSTATUS status;
	UNICODE_STRING  deviceDosName = { 0 };
	status = WallUnRegisterCallouts();
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[WFP_TEST]WallUnRegisterCallouts failed!\n");
		return;
	}
	RtlInitUnicodeString(&deviceDosName, DEVICE_DOSNAME);
	IoDeleteSymbolicLink(&deviceDosName);
	if (gDevObj)
	{
		IoDeleteDevice(gDevObj);
		gDevObj = NULL;
	}
	DbgPrint("[WFP_TEST] unloaded!\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
	UNREFERENCED_PARAMETER(registryPath);
	UNICODE_STRING  deviceName = { 0 };
	UNICODE_STRING  deviceDosName = { 0 };
	NTSTATUS status = STATUS_SUCCESS;
	driverObject->DriverUnload = DriverUnload;
	RtlInitUnicodeString(&deviceName, DEVICE_NAME);
	status = IoCreateDevice(driverObject,
		0,
		&deviceName,
		FILE_DEVICE_NETWORK,
		0,
		FALSE,
		&gDevObj);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[WFP_TEST]IoCreateDevice failed!\n");
		return STATUS_UNSUCCESSFUL;
	}
	gDevObj->Flags |= DO_BUFFERED_IO;
	RtlInitUnicodeString(&deviceDosName, DEVICE_DOSNAME);
	status = IoCreateSymbolicLink(&deviceDosName, &deviceName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[WFP_TEST]Create Symbolink name failed!\n");
		return STATUS_UNSUCCESSFUL;
	}
	//��ʼ���б�
	//InitializeListHead(&gPath_list);
	//��ʼ�������еķַ�����
	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
	{
		// IRP_MJ_MAXIMUM_FUNCTION �����ں����������зַ��������ܸ���
		// �����0x1b(27) + 1 ��.
		// �ַ������������MajorFunction���������
		/* ���ѭ�����ǰ����������еķַ�������ʼ����һ�����õķַ����� */
		driverObject->MajorFunction[i] = DispatchCommon;
	}
	driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctrl;
	status = WallRegisterCallouts();
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[WFP_TEST]WallRegisterCallouts failed!\n");
		return STATUS_UNSUCCESSFUL;
	}
	DbgPrint("[WFP_TEST] loaded! WallRegisterCallouts() success!\n");
	return status;
}