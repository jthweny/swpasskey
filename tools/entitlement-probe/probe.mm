// Minimal virtual FIDO HID device: the smallest possible reproduction of the
// entitlement gate, with none of swpasskey's code in the way.
//
// It builds a CTAP HID report descriptor (usage page 0xF1D0), asks IOKit for a
// user device, and prints one line: "device: CREATED" or "device: NULL". If this
// fails, no amount of work in swpasskeyd will make a key appear in a browser:
// the refusal happens in the kernel before any of our code runs.
#import <Foundation/Foundation.h>
#import <IOKit/hid/IOHIDKeys.h>
#import <IOKit/hidsystem/IOHIDUserDevice.h>

#include <unistd.h>

#include <cstdint>
#include <cstdio>

namespace {

// The FIDO HID descriptor: 64-byte input and output reports on usage page 0xF1D0.
constexpr std::uint8_t kCtapHidDescriptor[] = {
    0x06, 0xD0, 0xF1,  // Usage Page (FIDO Alliance)
    0x09, 0x01,        // Usage (CTAP HID)
    0xA1, 0x01,        // Collection (Application)
    0x09, 0x20,        //   Usage (Input Report Data)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x40,        //   Report Count (64)
    0x81, 0x00,        //   Input (Data, Array, Absolute)
    0x09, 0x21,        //   Usage (Output Report Data)
    0x15, 0x00,        //   Logical Minimum (0)
    0x26, 0xFF, 0x00,  //   Logical Maximum (255)
    0x75, 0x08,        //   Report Size (8)
    0x95, 0x40,        //   Report Count (64)
    0x91, 0x00,        //   Output (Data, Array, Absolute)
    0xC0,              // End Collection
};

}  // namespace

int main() {
  @autoreleasepool {
    NSDictionary* props = @{
      @(kIOHIDReportDescriptorKey) :
          [NSData dataWithBytes:kCtapHidDescriptor length:sizeof(kCtapHidDescriptor)],
      @(kIOHIDVendorIDKey) : @(0x1050),
      @(kIOHIDProductIDKey) : @(0x0407),
      @(kIOHIDVersionNumberKey) : @(0x0580),
      @(kIOHIDManufacturerKey) : @"Yubico (www.yubico.com)",
      @(kIOHIDProductKey) : @"entitlement probe",
      @(kIOHIDSerialNumberKey) : @"00000001",
      @(kIOHIDTransportKey) : @"USB",
      @(kIOHIDPrimaryUsagePageKey) : @(0xF1D0),
      @(kIOHIDPrimaryUsageKey) : @(0x01),
      @(kIOHIDMaxInputReportSizeKey) : @(64),
      @(kIOHIDMaxOutputReportSizeKey) : @(64),
    };
    IOHIDUserDeviceRef device =
        IOHIDUserDeviceCreateWithProperties(kCFAllocatorDefault, (__bridge CFDictionaryRef)props, 0);
    std::printf("pid: %d\n", static_cast<int>(getpid()));
    std::printf("device: %s\n", device != nullptr ? "CREATED" : "NULL");
    if (device != nullptr) {
      CFRelease(device);
    }
  }
  return 0;
}
