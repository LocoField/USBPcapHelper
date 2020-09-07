#pragma once

#include <Windows.h>

#define DEFAULT_SNAPSHOT_LENGTH             (65535)
#define DEFAULT_INTERNAL_KERNEL_BUFFER_SIZE (1024*1024)

class USBPcapHelper
{
public:
	USBPcapHelper();
	virtual ~USBPcapHelper() = default;

public:
	bool findDevice(USHORT idVendor, USHORT idProduct);
	bool start();
	void stop();
	bool isRunning();

protected:
	void readDataFromDevice();
	void processRawData(unsigned char* buffer, DWORD bytes);
	virtual void processInterruptData(unsigned char* buffer, DWORD bytes) = 0;

private:
	unsigned int snaplen = DEFAULT_SNAPSHOT_LENGTH;
	unsigned int bufferlen = DEFAULT_INTERNAL_KERNEL_BUFFER_SIZE;

	char* deviceAddr = nullptr;
	HANDLE deviceHandle;

	bool running = false;

};
