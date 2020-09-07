#include "USBPcapHelper.h"

#include <stdio.h>
#include <thread>
#include <functional>

#include <initguid.h>
#include <usbiodef.h>

#include "filters.h"
#include "enum.h"
#include "iocontrol.h"

struct FindDeviceContext
{
	USHORT idVendor;
	USHORT idProduct;
	UINT indexFound = 0;
};

struct DataHeader
{
	pcaprec_hdr_s recordHeader;
	USBPCAP_BUFFER_PACKET_HEADER packetHeader;
};

USBPcapHelper::USBPcapHelper()
{
}

bool USBPcapHelper::findDevice(USHORT idVendor, USHORT idProduct)
{
	filters_initialize();

	if (usbpcapFilters[0] == NULL)
	{
		printf("No filter control devices are available.\n");

		if (is_usbpcap_upper_filter_installed() == FALSE)
		{
			printf("Please reinstall USBPcap Driver.\n");
			return false;
		}
	}


	FindDeviceContext device;
	device.idVendor = idVendor;
	device.idProduct = idProduct;

	auto findConnectedDevice = [](HANDLE hub, ULONG port, USHORT deviceAddress, PUSB_DEVICE_DESCRIPTOR desc, void *ctx)
	{
		auto device = reinterpret_cast<FindDeviceContext*>(ctx);
		if (device == nullptr) return;

		if (desc->idVendor == device->idVendor &&
			desc->idProduct == device->idProduct)
		{
			device->indexFound = port;
		}
	};

	int i = 0;
	while (usbpcapFilters[i] != NULL)
	{
		enumerate_all_connected_devices(usbpcapFilters[i]->device, findConnectedDevice, &device);

		if (device.indexFound > 0)
		{
			deviceAddr = usbpcapFilters[i]->device;
			return true;
		}

		i++;
	}

	return false;
}

bool USBPcapHelper::start()
{
	USBPCAP_ADDRESS_FILTER filter;
	DWORD bytes_ret = 0;

	if (USBPcapInitAddressFilter(&filter, NULL, TRUE) == FALSE)
	{
		return false;
	}

	deviceHandle = CreateFileA(deviceAddr, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, 0);
	if (deviceHandle == INVALID_HANDLE_VALUE)
	{
		printf("Couldn't open device: %d\n", GetLastError());
		return false;
	}


	if (DeviceIoControl(deviceHandle, IOCTL_USBPCAP_SET_SNAPLEN_SIZE, &snaplen, sizeof(snaplen), NULL, 0, &bytes_ret, 0) == false)
	{
		printf("DeviceIoControl failed with %d status (supplimentary code %d)\n", GetLastError(), bytes_ret);
		goto FINISH;
	}

	if (DeviceIoControl(deviceHandle, IOCTL_USBPCAP_SETUP_BUFFER, &bufferlen, sizeof(bufferlen), NULL, 0, &bytes_ret, 0) == false)
	{
		printf("DeviceIoControl failed with %d status (supplimentary code %d)\n", GetLastError(), bytes_ret);
		goto FINISH;
	}

	if (DeviceIoControl(deviceHandle, IOCTL_USBPCAP_START_FILTERING, &filter, sizeof(filter), NULL, 0, &bytes_ret, 0) == false)
	{
		printf("DeviceIoControl failed with %d status (supplimentary code %d)\n", GetLastError(), bytes_ret);
		goto FINISH;
	}


	running = true;

	std::thread(std::bind(&USBPcapHelper::readDataFromDevice, this)).detach();
	return true;

FINISH:
	if (deviceHandle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(deviceHandle);
	}

	return false;
}

void USBPcapHelper::stop()
{
	running = false;
}

bool USBPcapHelper::isRunning()
{
	return running;
}

void USBPcapHelper::readDataFromDevice()
{
	OVERLAPPED readOverlapped;
	HANDLE readHandle;

	unsigned char* buffer = new unsigned char[bufferlen];
	memset(buffer, 0, bufferlen);

	memset(&readOverlapped, 0, sizeof(readOverlapped));
	readOverlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	readHandle = readOverlapped.hEvent;

	ReadFile(deviceHandle, buffer, bufferlen, NULL, &readOverlapped);

	while (running)
	{
		DWORD dw = WaitForSingleObject(readHandle, INFINITE);
		DWORD read;

		if (dw == WAIT_OBJECT_0)
		{
			GetOverlappedResult(deviceHandle, &readOverlapped, &read, TRUE);
			ResetEvent(readOverlapped.hEvent);

			processRawData(buffer, read);

			ReadFile(deviceHandle, buffer, bufferlen, &read, &readOverlapped);
		}
		else if (dw == WAIT_FAILED)
		{
			fprintf(stderr, "WaitForMultipleObjects failed in read_thread(): %d", GetLastError());
			break;
		}
	}

	CancelIo(deviceHandle);
	CloseHandle(deviceHandle);
	CloseHandle(readOverlapped.hEvent);

	if (buffer != NULL)
	{
		delete[] buffer;
	}
}

void USBPcapHelper::processRawData(unsigned char* buffer, DWORD bytes)
{
	// beginning with a USBPcap header
	if (bytes == sizeof(pcap_hdr_s))
	{
		// TODO: version handling
		return;
	}

	DataHeader header;
	memcpy(&header, buffer, sizeof(header));

	buffer += sizeof(header);
	bytes -= sizeof(header);

	if (header.packetHeader.function != URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER ||
		header.packetHeader.dataLength == 0)
	{
		return;
	}

	processInterruptData(buffer, header.packetHeader.dataLength);
}
