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
//内核分发函数

NTSTATUS DispatchCommon(PDEVICE_OBJECT pObject, PIRP pIrp) {

	UNREFERENCED_PARAMETER(pObject);
	// 这个成功是返回给R3的,因为R3也在等这次IRP处理的结果
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	// 表示Io的一些额外信息.
	// 比如在读写操作时表示实际读写的字节数
	// 在其他地方可能有更多的意思
	pIrp->IoStatus.Information = 0;

	// 结束掉这个IRP
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	// 这个return返回值是供IOManager使用,向IO框架提供处理结果
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

	// 虽然在R3中,Input和Output是2个Buffer,但在R0中是同一个
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
	以下两个回调函数没啥用
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

//协议代码转为名称
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

//最重要的过滤函数
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
	//在这里进行路径的判断，如果是我们拒绝的进程就进行拒绝操作，否则就放行
	classifyOut->actionType = FWP_ACTION_PERMIT;//允许连接
	//禁止IE联网（设置“行动类型”为FWP_ACTION_BLOCK）
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
	//要使用哪个设备对象注册
	status = FwpsCalloutRegister(gDevObj, &sCallout, calloutId);
	if (!NT_SUCCESS(status))
		goto exit;
	bCalloutRegistered = TRUE;
	mDispData.name = L"WFP TEST";
	mDispData.description = L"TESLA.ANGELA's WFP TEST";
	//你感兴趣的内容
	mCallout.applicableLayer = *layerKey;
	//你感兴趣的内容的GUID
	mCallout.calloutKey = *calloutKey;
	mCallout.displayData = mDispData;
	//添加回调函数
	status = FwpmCalloutAdd(gEngineHandle, &mCallout, NULL, NULL);
	if (!NT_SUCCESS(status))
		goto exit;
	mFilter.action.calloutKey = *calloutKey;
	//在callout里决定
	mFilter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	mFilter.displayData.name = L"WFP TEST";
	mFilter.displayData.description = L"TESLA.ANGELA's WFP TEST";
	mFilter.layerKey = *layerKey;
	mFilter.numFilterConditions = 0;
	mFilter.filterCondition = mFilter_condition;
	mFilter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
	mFilter.weight.type = FWP_EMPTY;
	//添加过滤器
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
	//开启WFP引擎
	status = FwpmEngineOpen(NULL,
		RPC_C_AUTHN_WINNT,
		NULL,
		&session,
		&gEngineHandle);
	if (!NT_SUCCESS(status))
		goto exit;
	bEngineOpened = TRUE;
	//确认过滤权限
	status = FwpmTransactionBegin(gEngineHandle, 0);
	if (!NT_SUCCESS(status))
		goto exit;
	bInTransaction = TRUE;
	//注册回调函数
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
	//确认所有内容并提交，让回调函数正式发挥作用
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
		//删除FilterId
		FwpmFilterDeleteById(gEngineHandle, gAleConnectFilterId);
		//删除CalloutId
		FwpmCalloutDeleteById(gEngineHandle, gAleConnectCalloutId);
		//清空FilterId
		gAleConnectFilterId = 0;
		//反注册CalloutId
		FwpsCalloutUnregisterById(gAleConnectCalloutId);
		//清空CalloutId
		gAleConnectCalloutId = 0;
		//关闭引擎
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
	//初始化列表
	//InitializeListHead(&gPath_list);
	//初始化驱动中的分发函数
	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
	{
		// IRP_MJ_MAXIMUM_FUNCTION 代表内核驱动对象中分发函数的总个数
		// 最大是0x1b(27) + 1 个.
		// 分发函数都存放在MajorFunction这个数组中
		/* 这个循环就是把驱动对象中的分发函数初始化成一个公用的分发函数 */
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